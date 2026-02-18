# @haldir/scanner

Static analysis engine for agent skills. Detects malicious patterns using 70 regex-based rules across 7 threat categories.

## What This Package Does

Scans agent skill directories for security threats:
- **Exfiltration** - Environment harvesting, data leaks, context exposure
- **Privilege escalation** - sudo, credential access, allowed tool abuse
- **Supply chain** - Unpinned deps, curl|sh, obfuscated execution
- **Prompt injection** - Instruction override, hidden directives
- **Persistence** - Reverse shells, memory poisoning, cron jobs
- **Campaign indicators** - Paste services, URL shorteners, C2 channels
- **Credential exposure** - API keys, tokens, private keys in code

## Installation

```bash
npm install @haldir/scanner
```

## Quick Start

```typescript
import { scanDirectory } from '@haldir/scanner';

const result = await scanDirectory('./my-skill');

console.log(`Status: ${result.status}`); // 'pass' | 'flag' | 'reject'
console.log(`Files scanned: ${result.files_scanned}`);
console.log(`Findings: ${result.findings.length}`);
console.log(`Summary: ${JSON.stringify(result.summary)}`);

// Check findings
for (const finding of result.findings) {
  console.log(`[${finding.severity}] ${finding.file}:${finding.line}`);
  console.log(`  ${finding.message}`);
  console.log(`  Match: ${finding.match}`);
}
```

## CLI Usage

```bash
# Scan a skill directory
haldir scan ./my-skill

# JSON output
haldir scan ./my-skill --json

# Only report high/critical
haldir scan ./my-skill --severity high

# Fail on any finding
haldir scan ./my-skill --strict
```

## API

### `scanDirectory(dirPath, config?)`

Scans a directory for security threats.

**Parameters:**

```typescript
interface ScanConfig {
  // Maximum files to scan (default: 10,000)
  maxFiles?: number;

  // Maximum file size (default: 10MB)
  maxFileSize?: number;

  // Directories to skip (default: ['.vault', 'node_modules', '.git', '__pycache__'])
  skipDirs?: string[];

  // Minimum severity to report (default: 'low')
  severityThreshold?: 'low' | 'medium' | 'high' | 'critical';

  // Custom patterns (default: PATTERN_DB)
  patterns?: ThreatPattern[];

  // Stop on first critical finding (default: false)
  stopOnFirstCritical?: boolean;
}
```

**Returns:** `Promise<ScanResult>`

```typescript
interface ScanResult {
  // Overall assessment
  status: 'pass' | 'flag' | 'reject';

  // Performance metrics
  duration_ms: number;
  files_scanned: number;
  files_skipped: number;
  patterns_checked: number;

  // Findings
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface Finding {
  pattern_id: string;          // e.g. 'env_harvest_node'
  category: ThreatCategory;    // e.g. 'exfiltration'
  severity: Severity;          // 'critical' | 'high' | 'medium' | 'low'
  file: string;                // relative path from skill root
  line: number;                // 1-indexed
  column: number;              // 0-indexed
  match: string;               // matched substring
  context: string;             // full line
  message: string;             // human-readable description
}
```

## Status Mapping

| Severity | Status |
|----------|--------|
| Any critical | **reject** |
| Any high/medium | **flag** |
| Only low | **pass** |
| No findings | **pass** |

## Threat Categories

### 1. Exfiltration (E1-E4)

Detects data extraction attempts:

| Pattern | Example |
|---------|---------|
| `env_harvest_node` | `process.env` |
| `env_harvest_python` | `os.environ` |
| `fs_enumerate_*` | `fs.readdir`, `os.listdir` |
| `data_exfil_*` | HTTP POST with large payloads |
| `context_leakage` | Agent context in network requests |

**Severity:** High

### 2. Privilege Escalation (PE1-PE3)

Detects privilege abuse:

| Pattern | Example |
|---------|---------|
| `sudo_escalation` | `sudo`, `doas` |
| `credential_access` | `/etc/passwd`, `~/.ssh/` |
| `allowed_tool_abuse` | Misuse of declared capabilities |
| `docker_socket_access` | `/var/run/docker.sock` |
| `proc_access` | `/proc/*/environ` |

**Severity:** High

### 3. Supply Chain (SC1-SC3)

Detects dependency attacks:

| Pattern | Example |
|---------|---------|
| `unpinned_deps` | `^1.0.0`, `>=2.0.0` |
| `curl_pipe_sh` | `curl ... \| sh` |
| `obfuscated_exec` | `eval(atob(...))` |
| `base64_pipe` | Base64-encoded commands |
| `git_deps` | `"dep": "git://..."` |

**Severity:** Critical (curl\|sh), High (others)

### 4. Prompt Injection (P1-P4)

Detects prompt manipulation:

| Pattern | Example |
|---------|---------|
| `instruction_override` | "Ignore previous instructions" |
| `hidden_unicode` | Zero-width characters |
| `persona_override` | "You are now..." |
| `exfil_command` | Hidden commands in prompts |

**Severity:** High/Critical

### 5. Persistence

Detects persistent backdoors:

| Pattern | Example |
|---------|---------|
| `reverse_shell` | `nc -e /bin/bash` |
| `memory_poison` | Mnemo corruption attempts |
| `cron_install` | `crontab -e` |
| `startup_script` | `~/.bashrc` modification |

**Severity:** Critical

### 6. Campaign Indicators

Detects organized attacks:

| Pattern | Example |
|---------|---------|
| `paste_service` | `pastebin.com`, `hastebin` |
| `url_shortener` | `bit.ly`, `tinyurl` |
| `c2_channel` | Known C2 domains |

**Severity:** Medium

### 7. Credential Exposure

Detects hardcoded secrets:

| Pattern | Example |
|---------|---------|
| `aws_key` | `AKIA[A-Z0-9]{16}` |
| `openai_key` | `sk-[A-Za-z0-9]{48}` |
| `stripe_key` | `sk_live_[A-Za-z0-9]+` |
| `github_token` | `ghp_[A-Za-z0-9]+` |
| `private_key_marker` | `-----BEGIN PRIVATE KEY-----` |
| `jwt_token` | `eyJ[A-Za-z0-9-_]+\.eyJ...` |

**Severity:** High/Critical

## Performance

- **Speed:** ~1s for typical skill (10-20 files)
- **Scalability:** 10,000 files in <30s
- **Pattern count:** 70 pre-compiled regex patterns
- **Extension filtering:** Patterns only run on relevant file types

## Limitations

### What Scanner Catches

✅ Known malicious patterns (environment harvesting, reverse shells)
✅ Credential exposure (API keys, tokens)
✅ Suspicious commands (curl\|sh, sudo, base64)
✅ Supply chain issues (unpinned deps, git dependencies)

### What Scanner Misses

❌ **Complex dataflow obfuscation** — Multi-step variable chains across many lines may evade both line-by-line and multiline regex. Full AST/dataflow analysis is not implemented.
❌ **Semantic malice** — Requires LLM audit (see [@haldir/reviewer](../reviewer))
❌ **Runtime behavior** — Sandbox testing needed (see [@haldir/sandbox](../sandbox))
❌ **Zero-day patterns** — Not in pattern database until added
❌ **Novel typosquats** — Levenshtein detection covers ~90 popular packages; less popular package typosquats may not be caught
❌ **External registry validation** — Cannot verify whether a dependency name exists on npm

**Recommendation:** Use scanner as **Layer 1** of a multi-layer pipeline. Combine with:
- **Layer 2:** [@haldir/auditor](../auditor) - dependency auditing
- **Layer 3:** [@haldir/sandbox](../sandbox) - runtime analysis
- **Layer 4:** [@haldir/reviewer](../reviewer) - LLM semantic audit

See [@haldir/pipeline](../pipeline) for full vetting orchestration.

## Custom Patterns

```typescript
import { scanDirectory, type ThreatPattern } from '@haldir/scanner';

const customPatterns: ThreatPattern[] = [
  {
    id: 'my_custom_check',
    category: 'exfiltration',
    severity: 'high',
    name: 'Custom data exfiltration check',
    regex: /sendDataToAttacker\(/,
    fileExtensions: ['.js', '.ts'],
    description: 'Detects calls to sendDataToAttacker function'
  }
];

const result = await scanDirectory('./skill', {
  patterns: customPatterns
});
```

## Exit Codes (CLI)

| Code | Meaning |
|------|---------|
| 0 | Scan passed (no findings or only low severity) |
| 1 | Findings detected (reject or flag + --strict) |
| 2 | Error (invalid arguments, filesystem error) |

## See Also

- **[@haldir/auditor](../auditor)** - Layer 2: Dependency auditing
- **[@haldir/sandbox](../sandbox)** - Layer 3: Runtime analysis
- **[@haldir/reviewer](../reviewer)** - Layer 4: LLM semantic audit
- **[@haldir/pipeline](../pipeline)** - Full vetting orchestration
- **[Root README](../../README.md)** - Quick start guide

## License

Apache 2.0
