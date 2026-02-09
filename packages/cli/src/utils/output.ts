import type { VerifyResult, CLIOutput } from '@haldir/core';

export function toCliOutput(result: VerifyResult): CLIOutput {
  return {
    valid: result.valid,
    trustLevel: result.trustLevel,
    keyId: result.keyId ?? null,
    warnings: result.warnings.map((w) => ({ code: w.code, message: w.message })),
    errors: result.errors.map((e) => ({ code: e.code, message: e.message, ...(e.file ? { file: e.file } : {}) })),
    attestation: result.attestation ?? null,
    permissions: result.permissions ?? null,
  };
}
