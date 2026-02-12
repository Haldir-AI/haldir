# @haldir/sandbox

Lightweight test runner for agent skills with resource limits and output analysis.

## Security Notice

**⚠️ This is NOT a security sandbox.**

This package provides:
- ✅ Timeout enforcement
- ✅ Memory limits
- ✅ Output analysis for suspicious patterns
- ❌ **NO filesystem isolation**
- ❌ **NO network isolation**
- ❌ **NO privilege separation**

**For production permission enforcement, use `@haldir/enforcer` with OS-level sandboxing (Node.js permissions, Linux Landlock, or macOS sandbox-exec).**

## Purpose

The sandbox package is designed for **pipeline testing (Layer 4)** to detect:
- Runtime crashes
- Suspicious output patterns (network attempts, file access)
- Resource exhaustion
- Behavioral anomalies

It is NOT designed to prevent malicious code execution.

## Usage

```typescript
import { sandboxSkill } from '@haldir/sandbox';

const result = await sandboxSkill('/path/to/skill', {
  timeout: 5000,
  maxMemory: 256,
  allowNetwork: false,
});

console.log(result.status); // 'pass' | 'flag' | 'reject'
console.log(result.violations);
```

## See Also

- `@haldir/enforcer` — Production permission enforcement
- `@haldir/pipeline` — Full 5-layer vetting pipeline
