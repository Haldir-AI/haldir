/**
 * Context-Aware Scanner Utilities
 *
 * SECURITY PRINCIPLES:
 * 1. Don't use name inference for security decisions (gameable)
 * 2. Use signed permissions.json as primary signal
 * 3. Expected capabilities ≠ Safe capabilities (require consent)
 * 4. Keep supply-chain patterns at MEDIUM minimum (no LOW downgrade)
 * 5. Test findings = separate channel (visibility without blocking)
 */

import type {
  Finding,
  ContextualFinding,
  FileClassification,
  ConsentRequirement,
  Severity,
} from './types.js';

/**
 * Classify file by location and extension
 * Used for context understanding, NOT for security suppression
 */
export function classifyFile(filepath: string): FileClassification {
  const normalized = filepath.toLowerCase();

  // Test files (separate channel, not production)
  if (
    normalized.includes('/__tests__/') ||
    normalized.includes('/test/') ||
    normalized.includes('/tests/') ||
    normalized.startsWith('test/') ||    // FIX: paths without leading slash
    normalized.startsWith('tests/') ||
    normalized.match(/\.(test|spec)\.(js|ts|jsx|tsx|py|rb|go|rs)$/)
  ) {
    return 'test';
  }

  // Documentation (installation instructions, not executable)
  if (
    normalized.endsWith('.md') ||
    normalized.endsWith('.txt') ||
    normalized.endsWith('.rst') ||
    normalized === 'readme' ||
    normalized.includes('/docs/')
  ) {
    return 'documentation';
  }

  // Build/CI (often copy-pasted or auto-run - keep vigilant!)
  // Check BEFORE configuration files (to catch .yml in .github/workflows/)
  if (
    normalized.includes('/.github/workflows/') ||
    normalized.startsWith('.github/workflows/') ||  // FIX: paths without leading slash
    normalized.includes('/.gitlab-ci') ||
    normalized.startsWith('.gitlab-ci') ||
    normalized.includes('/github/') ||
    normalized === 'dockerfile' ||
    normalized.endsWith('.dockerfile') ||
    normalized.includes('docker-compose')
  ) {
    return 'build';
  }

  // Configuration files
  if (normalized.match(/\.(json|yaml|yml|toml|ini|cfg|env)$/)) {
    return 'configuration';
  }

  // Production code (default)
  return 'production';
}

/**
 * High-risk capabilities that require explicit user consent
 * Even when declared in permissions.json, these remain dangerous
 */
const CONSENT_REQUIRED_CAPABILITIES: Record<string, ConsentRequirement> = {
  'docker.sock': {
    capability: 'docker.sock',
    riskLevel: 'critical',
    explanation: 'Docker socket access grants root-equivalent privileges on host system',
    mitigation: 'Only grant to trusted skills. User must explicitly consent to container control.',
  },

  'kubeconfig': {
    capability: 'kubernetes',
    riskLevel: 'critical',
    explanation: 'Kubernetes cluster access can modify/delete production infrastructure',
    mitigation: 'Only grant to trusted skills. User must explicitly consent to cluster operations.',
  },

  'filesystem.write': {
    capability: 'filesystem.write',
    riskLevel: 'high',
    explanation: 'Write access can modify, delete, or corrupt files',
    mitigation: 'User should review which directories this skill can write to.',
  },

  'filesystem.execute': {
    capability: 'filesystem.execute',
    riskLevel: 'high',
    explanation: 'Execute permission can run arbitrary commands',
    mitigation: 'User must explicitly consent to command execution.',
  },

  'process.spawn': {
    capability: 'process.spawn',
    riskLevel: 'high',
    explanation: 'Can spawn child processes and execute commands',
    mitigation: 'Review what commands this skill executes.',
  },
};

/**
 * FIX #3: Pattern ID to capability mapping (normalized, not ad-hoc text matching)
 * Maps threat patterns to their semantic capabilities
 */
const PATTERN_TO_CAPABILITY: Record<string, string> = {
  // Docker patterns
  'docker_socket_access': 'docker.sock',
  'docker_escalation': 'docker.sock',

  // Kubernetes patterns
  'kubectl_usage': 'kubeconfig',
  'k8s_api': 'kubeconfig',

  // Filesystem patterns
  'fs_write': 'filesystem.write',
  'fs_delete': 'filesystem.write',
  'fs_chmod': 'filesystem.execute',
  'fs_exec': 'filesystem.execute',

  // Process patterns
  'child_process_spawn': 'process.spawn',
  'child_process_exec': 'process.spawn',
  'subprocess_popen': 'process.spawn',

  // Network patterns
  'network_fetch': 'network.fetch',

  // Add more mappings as needed
};

/**
 * Check if finding matches a high-risk capability
 * Returns consent requirement if found
 *
 * FIX #3: Use normalized capability matching via pattern ID
 * Fallback to text matching for patterns without explicit mapping
 */
function checkConsentRequired(finding: Finding): ConsentRequirement | undefined {
  // Primary: Check pattern ID mapping (normalized)
  const mappedCapability = PATTERN_TO_CAPABILITY[finding.pattern_id];
  if (mappedCapability && CONSENT_REQUIRED_CAPABILITIES[mappedCapability]) {
    return CONSENT_REQUIRED_CAPABILITIES[mappedCapability];
  }

  // Fallback: Check match text (for patterns not yet mapped)
  const match = finding.match.toLowerCase();
  for (const [key, consent] of Object.entries(CONSENT_REQUIRED_CAPABILITIES)) {
    if (match.includes(key.toLowerCase())) {
      return consent;
    }
  }

  return undefined;
}

/**
 * Apply context-aware analysis to a finding
 *
 * RULES:
 * 1. NEVER suppress HIGH/CRITICAL supply-chain findings to LOW
 * 2. Expected capabilities still require consent if high-risk
 * 3. Test findings go to separate channel
 * 4. Context reason is MANDATORY
 */
export function applyContextAwareness(
  finding: Finding,
  fileClass: FileClassification,
  declaredCapabilities: string[] = []
): ContextualFinding {
  let adjustedSeverity: Severity = finding.severity;
  let contextReason: string;
  let consentRequired: ConsentRequirement | undefined;

  // 1. Test files - informational only (separate channel)
  if (fileClass === 'test') {
    adjustedSeverity = 'low';
    contextReason = 'Test infrastructure (informational only, not production code)';
    return {
      ...finding,
      severity: adjustedSeverity,  // Override severity with adjusted value
      originalSeverity: finding.severity,
      adjustedSeverity,
      fileClassification: fileClass,
      contextReason,
    };
  }

  // 2. Check if this requires explicit consent
  consentRequired = checkConsentRequired(finding);

  // 3. Documentation files
  if (fileClass === 'documentation') {
    if (finding.category === 'supply_chain') {
      // Supply-chain in docs: MEDIUM minimum (not LOW!)
      // Reason: Often copy-pasted or auto-run
      if (finding.severity === 'critical') {
        adjustedSeverity = 'medium';
        contextReason = 'Installation instructions (not directly executed, but often copy-pasted)';
      } else {
        adjustedSeverity = finding.severity;
        contextReason = 'Supply-chain pattern in documentation (verify if executable)';
      }
    } else {
      // Non-supply-chain in docs: Can downgrade
      if (finding.severity === 'high' || finding.severity === 'critical') {
        adjustedSeverity = 'low';
        contextReason = 'Example code in documentation (not production)';
      } else {
        adjustedSeverity = finding.severity;
        contextReason = 'Documentation reference (not executed)';
      }
    }
  }

  // 4. Build/CI files
  else if (fileClass === 'build') {
    // Build/CI: Keep at least MEDIUM for supply-chain
    if (finding.category === 'supply_chain' && finding.severity === 'critical') {
      adjustedSeverity = 'high'; // Downgrade from critical, but keep high
      contextReason = 'CI/CD pipeline (executes on build - review for security)';
    } else {
      adjustedSeverity = finding.severity;
      contextReason = 'Build/CI file (executes automatically - keep vigilant)';
    }
  }

  // 5. Declared capabilities (from signed permissions.json)
  else if (declaredCapabilities.length > 0) {
    // Check if pattern maps to a capability, then check if that capability is declared
    const mappedCapability = PATTERN_TO_CAPABILITY[finding.pattern_id];
    const isDeclaredViaMappedCapability = mappedCapability && declaredCapabilities.includes(mappedCapability);

    // Also check if pattern_id itself is in declared capabilities (backwards compat)
    const isDeclaredViaPatternId = declaredCapabilities.includes(finding.pattern_id);

    // Fallback: check if any declared capability appears in match text
    const isDeclaredViaTextMatch = declaredCapabilities.some((cap) =>
      finding.match.toLowerCase().includes(cap.toLowerCase())
    );

    const isDeclared = isDeclaredViaMappedCapability || isDeclaredViaPatternId || isDeclaredViaTextMatch;

    if (isDeclared) {
      // Capability is declared in signed permissions.json
      if (consentRequired) {
        // Still high-risk, but expected
        adjustedSeverity = finding.severity; // KEEP HIGH
        contextReason = `Declared capability (expected but requires user consent: ${consentRequired.explanation})`;
      } else {
        // Declared and not particularly dangerous
        if (finding.severity === 'high') {
          adjustedSeverity = 'medium';
          contextReason = 'Declared capability (expected behavior per permissions.json)';
        } else {
          adjustedSeverity = finding.severity;
          contextReason = 'Declared capability';
        }
      }
    } else {
      // Not declared - suspicious!
      adjustedSeverity = finding.severity;
      contextReason = 'NOT declared in permissions.json (unexpected behavior - verify intent)';
      consentRequired = undefined; // Remove consent since it's undeclared
    }
  }

  // 6. Production code without declared capabilities
  else {
    adjustedSeverity = finding.severity;
    contextReason = 'Production code (no permissions.json found - all patterns flagged)';
  }

  return {
    ...finding,
    severity: adjustedSeverity,  // Override severity with adjusted value for backwards compatibility
    originalSeverity: finding.severity,
    adjustedSeverity,
    fileClassification: fileClass,
    contextReason,
    consentRequired,
  };
}

/**
 * Known safe emoji sequences with zero-width joiners
 * Explicit allowlist to avoid fragile regex approaches
 */
const SAFE_EMOJI_SEQUENCES = new Set([
  '🧑\u200D💻', // Technologist (person + ZWJ + laptop)
  '👨\u200D💻', // Man technologist
  '👩\u200D💻', // Woman technologist
  '👨\u200D🔧', // Man mechanic
  '👩\u200D🔧', // Woman mechanic
  '👨\u200D🔬', // Man scientist
  '👩\u200D🔬', // Woman scientist
  // Add more as needed
]);

/**
 * Check if a zero-width character is part of a safe emoji sequence
 * Returns true if it's a legitimate emoji, false if suspicious
 */
export function isSafeEmojiSequence(text: string, position: number): boolean {
  // Check if the ZWJ is part of any known safe emoji sequence
  for (const emoji of SAFE_EMOJI_SEQUENCES) {
    const startPos = position - 2; // ZWJ is typically at position 2 in emoji
    if (startPos >= 0) {
      const substr = text.substring(startPos, startPos + emoji.length);
      if (substr === emoji) {
        return true;
      }
    }
  }

  // Check next few characters too (ZWJ might be at different positions)
  const window = text.substring(Math.max(0, position - 3), position + 4);
  for (const emoji of SAFE_EMOJI_SEQUENCES) {
    if (window.includes(emoji)) {
      return true;
    }
  }

  return false;
}

/**
 * Enhanced Unicode scanning that's grapheme-aware
 * ONLY scans for ZWJ (\u200D) with emoji context awareness
 * Other hidden Unicode characters are handled by the hidden_text_unicode pattern
 */
export function scanForSuspiciousUnicode(content: string, _filepath?: string): boolean {
  // Only scan for Zero-Width Joiner (ZWJ) - other hidden chars handled by patterns
  const zwChars = /\u200D/g;
  let match: RegExpExecArray | null;

  while ((match = zwChars.exec(content)) !== null) {
    const pos = match.index;

    // Check if this is part of a safe emoji sequence
    if (!isSafeEmojiSequence(content, pos)) {
      return true; // Suspicious hidden character found
    }
  }

  return false;
}
