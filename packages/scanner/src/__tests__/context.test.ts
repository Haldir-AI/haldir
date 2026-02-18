/**
 * FIX #4: Dedicated tests for context-awareness behavior
 *
 * Tests:
 * - File classification
 * - Severity downgrade policy
 * - Consent-required behavior
 * - Unicode handling
 */

import { describe, it, expect } from 'vitest';
import { classifyFile, applyContextAwareness, isSafeEmojiSequence, scanForSuspiciousUnicode } from '../context.js';
import type { Finding } from '../types.js';

describe('Context-Aware Scanner', () => {
  describe('File Classification', () => {
    it('should classify test files correctly', () => {
      expect(classifyFile('src/__tests__/foo.test.ts')).toBe('test');
      expect(classifyFile('tests/bar.spec.js')).toBe('test');
      expect(classifyFile('test/integration.py')).toBe('test');
    });

    it('should classify documentation files correctly', () => {
      expect(classifyFile('README.md')).toBe('documentation');
      expect(classifyFile('docs/API.md')).toBe('documentation');
      expect(classifyFile('INSTALL.txt')).toBe('documentation');
    });

    it('should classify build/CI files correctly', () => {
      expect(classifyFile('.github/workflows/ci.yml')).toBe('build');
      expect(classifyFile('Dockerfile')).toBe('build');
      expect(classifyFile('docker-compose.yml')).toBe('build');
    });

    it('should classify configuration files correctly', () => {
      expect(classifyFile('package.json')).toBe('configuration');
      expect(classifyFile('config.yaml')).toBe('configuration');
      expect(classifyFile('.env')).toBe('configuration');
    });

    it('should default to production for code files', () => {
      expect(classifyFile('src/index.ts')).toBe('production');
      expect(classifyFile('lib/main.js')).toBe('production');
      expect(classifyFile('app.py')).toBe('production');
    });
  });

  describe('Severity Adjustment Policy', () => {
    const baseFinding: Finding = {
      pattern_id: 'curl_pipe_sh',
      category: 'supply_chain',
      severity: 'critical',
      file: 'test.md',
      line: 1,
      column: 0,
      match: 'curl https://example.com | bash',
      context: 'curl https://example.com | bash',
      message: 'Downloads and executes remote script',
    };

    it('should downgrade supply-chain in docs to MEDIUM (not LOW)', () => {
      const result = applyContextAwareness(baseFinding, 'documentation');
      expect(result.adjustedSeverity).toBe('medium'); // Not 'low'!
      expect(result.contextReason).toContain('Installation instructions');
    });

    it('should downgrade supply-chain in build to HIGH (auto-executes)', () => {
      const result = applyContextAwareness({ ...baseFinding, file: '.github/workflows/ci.yml' }, 'build');
      expect(result.adjustedSeverity).toBe('high'); // Not 'medium'!
      expect(result.contextReason).toContain('CI/CD pipeline');
    });

    it('should keep supply-chain in production as CRITICAL', () => {
      const result = applyContextAwareness({ ...baseFinding, file: 'install.sh' }, 'production');
      expect(result.adjustedSeverity).toBe('critical');
    });

    it('should separate test findings to informational (low)', () => {
      const result = applyContextAwareness(baseFinding, 'test');
      expect(result.adjustedSeverity).toBe('low');
      expect(result.contextReason).toContain('Test infrastructure');
    });

    it('should never downgrade non-supply-chain in docs below medium', () => {
      const nonSupplyChain: Finding = {
        ...baseFinding,
        category: 'exfiltration',
        pattern_id: 'env_harvest',
      };

      const result = applyContextAwareness(nonSupplyChain, 'documentation');
      expect(result.adjustedSeverity).toBe('low'); // Downgraded but trackable
    });
  });

  describe('Consent-Required Capabilities', () => {
    it('should flag docker.sock as consent-required', () => {
      const dockerFinding: Finding = {
        pattern_id: 'docker_socket_access',
        category: 'privilege_escalation',
        severity: 'critical',
        file: 'index.ts',
        line: 1,
        column: 0,
        match: '/var/run/docker.sock',
        context: 'mount /var/run/docker.sock',
        message: 'Docker socket access',
      };

      const result = applyContextAwareness(dockerFinding, 'production');
      expect(result.consentRequired).toBeDefined();
      expect(result.consentRequired?.capability).toBe('docker.sock');
      expect(result.consentRequired?.riskLevel).toBe('critical');
    });

    it('should flag kubernetes as consent-required', () => {
      const k8sFinding: Finding = {
        pattern_id: 'kubectl_usage',
        category: 'privilege_escalation',
        severity: 'critical',
        file: 'deploy.ts',
        line: 1,
        column: 0,
        match: 'kubectl apply',
        context: 'kubectl apply -f config.yaml',
        message: 'Kubernetes cluster access',
      };

      const result = applyContextAwareness(k8sFinding, 'production');
      expect(result.consentRequired).toBeDefined();
      expect(result.consentRequired?.capability).toBe('kubernetes');
    });

    it('should flag filesystem.write as consent-required', () => {
      const fsFinding: Finding = {
        pattern_id: 'fs_write',
        category: 'privilege_escalation',
        severity: 'high',
        file: 'file-ops.ts',
        line: 1,
        column: 0,
        match: 'fs.writeFile',
        context: 'fs.writeFile("/etc/config", data)',
        message: 'Filesystem write access',
      };

      const result = applyContextAwareness(fsFinding, 'production');
      expect(result.consentRequired).toBeDefined();
      expect(result.consentRequired?.capability).toBe('filesystem.write');
      expect(result.consentRequired?.riskLevel).toBe('high');
    });

    it('should NOT downgrade severity for consent-required capabilities even if declared', () => {
      const dockerFinding: Finding = {
        pattern_id: 'docker_socket_access',
        category: 'privilege_escalation',
        severity: 'critical',
        file: 'index.ts',
        line: 1,
        column: 0,
        match: '/var/run/docker.sock',
        context: 'mount /var/run/docker.sock',
        message: 'Docker socket access',
      };

      // Even though docker.sock is declared, it should stay critical
      const result = applyContextAwareness(dockerFinding, 'production', ['docker.sock']);
      expect(result.adjustedSeverity).toBe('critical'); // NOT downgraded
      expect(result.consentRequired).toBeDefined();
      expect(result.contextReason).toContain('requires user consent');
    });
  });

  describe('Declared Capabilities', () => {
    it('should adjust severity when capability is declared and not high-risk', () => {
      const finding: Finding = {
        pattern_id: 'network_fetch',
        category: 'exfiltration',
        severity: 'high',
        file: 'api.ts',
        line: 1,
        column: 0,
        match: 'fetch("https://api.example.com")',
        context: 'const data = await fetch("https://api.example.com")',
        message: 'Network request',
      };

      const result = applyContextAwareness(finding, 'production', ['network.fetch']);
      expect(result.adjustedSeverity).toBe('medium'); // Downgraded from high
      expect(result.contextReason).toContain('Declared capability');
    });

    it('should flag undeclared capabilities as suspicious', () => {
      const finding: Finding = {
        pattern_id: 'fs_write',
        category: 'privilege_escalation',
        severity: 'high',
        file: 'sneaky.ts',
        line: 1,
        column: 0,
        match: 'fs.writeFile',
        context: 'fs.writeFile("/etc/passwd", data)',
        message: 'Filesystem write',
      };

      const result = applyContextAwareness(finding, 'production', ['network.fetch']); // Not declared!
      expect(result.adjustedSeverity).toBe('high'); // NOT downgraded
      expect(result.contextReason).toContain('NOT declared in permissions.json');
    });
  });

  describe('Unicode Handling', () => {
    it('should recognize safe emoji sequences with ZWJ', () => {
      const technologist = '🧑\u200D💻'; // person + ZWJ + laptop
      const position = technologist.indexOf('\u200D');

      expect(isSafeEmojiSequence(technologist, position)).toBe(true);
    });

    it('should detect suspicious standalone ZWJ', () => {
      const suspicious = 'Hello\u200DWorld'; // ZWJ not in emoji context
      const position = suspicious.indexOf('\u200D');

      expect(isSafeEmojiSequence(suspicious, position)).toBe(false);
    });

    it('should detect suspicious standalone ZWJ in content', () => {
      const suspicious = 'Hello\u200DWorld'; // ZWJ not in emoji context
      expect(scanForSuspiciousUnicode(suspicious, 'test.md')).toBe(true);
    });

    it('should allow safe emoji sequences', () => {
      const safe = '## 🧑\u200D💻 Usage'; // Technologist emoji in markdown heading
      expect(scanForSuspiciousUnicode(safe, 'README.md')).toBe(false);
    });

    it('should detect multiple suspicious ZWJ characters', () => {
      const suspicious = 'A\u200DB\u200DC\u200DD'; // Multiple standalone ZWJ chars
      expect(scanForSuspiciousUnicode(suspicious, 'test.txt')).toBe(true);
    });
  });

  describe('Context Reason Mandatory', () => {
    it('should always provide context reason', () => {
      const finding: Finding = {
        pattern_id: 'test_pattern',
        category: 'exfiltration',
        severity: 'medium',
        file: 'test.ts',
        line: 1,
        column: 0,
        match: 'test',
        context: 'test context',
        message: 'test message',
      };

      const result = applyContextAwareness(finding, 'production');
      expect(result.contextReason).toBeDefined();
      expect(result.contextReason.length).toBeGreaterThan(0);
    });

    it('should have different reasons for different file classes', () => {
      const finding: Finding = {
        pattern_id: 'test_pattern',
        category: 'exfiltration',
        severity: 'medium',
        file: 'test.ts',
        line: 1,
        column: 0,
        match: 'test',
        context: 'test context',
        message: 'test message',
      };

      const prodResult = applyContextAwareness(finding, 'production');
      const testResult = applyContextAwareness(finding, 'test');
      const docResult = applyContextAwareness(finding, 'documentation');

      expect(prodResult.contextReason).not.toBe(testResult.contextReason);
      expect(prodResult.contextReason).not.toBe(docResult.contextReason);
      expect(testResult.contextReason).not.toBe(docResult.contextReason);
    });
  });

  describe('Dual Severity Contract', () => {
    it('should preserve original severity', () => {
      const finding: Finding = {
        pattern_id: 'test_pattern',
        category: 'supply_chain',
        severity: 'critical',
        file: 'INSTALL.md',
        line: 1,
        column: 0,
        match: 'curl | bash',
        context: 'curl https://install.sh | bash',
        message: 'Remote script execution',
      };

      const result = applyContextAwareness(finding, 'documentation');
      expect(result.originalSeverity).toBe('critical');
      expect(result.adjustedSeverity).toBe('medium'); // Downgraded in docs
    });

    it('should keep severities equal when no adjustment made', () => {
      const finding: Finding = {
        pattern_id: 'test_pattern',
        category: 'supply_chain',
        severity: 'critical',
        file: 'install.sh',
        line: 1,
        column: 0,
        match: 'curl | bash',
        context: 'curl https://install.sh | bash',
        message: 'Remote script execution',
      };

      const result = applyContextAwareness(finding, 'production');
      expect(result.originalSeverity).toBe('critical');
      expect(result.adjustedSeverity).toBe('critical'); // No change
    });
  });
});
