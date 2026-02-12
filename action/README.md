# Haldir Sign Action

GitHub Action to sign agent skills with Haldir. Creates a `.vault/` security envelope with cryptographic signatures, integrity hashes, and permission declarations.

## Usage

### Keyless Signing (Sigstore)

No secrets needed. Signs with your GitHub Actions OIDC identity.

```yaml
name: Sign Skill
on: [push]

permissions:
  id-token: write  # Required for Sigstore OIDC
  contents: read

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: haldir-ai/sign-action@v1
        with:
          skill-dir: ./my-skill
          skill-name: my-skill
          skill-version: '1.0.0'
```

### Ed25519 Key Signing

```yaml
      - uses: haldir-ai/sign-action@v1
        with:
          skill-dir: ./my-skill
          mode: key
          private-key: ${{ secrets.HALDIR_PRIVATE_KEY }}
          skill-name: my-skill
          skill-version: '1.0.0'
```

### Co-signing (Dual-Sign)

Add a second signature to an already-signed skill:

```yaml
      - uses: haldir-ai/sign-action@v1
        with:
          skill-dir: ./my-skill
          cosign: 'true'
          private-key: ${{ secrets.AUTHORITY_KEY }}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `skill-dir` | Yes | | Path to skill directory |
| `mode` | No | `keyless` | `keyless` (Sigstore) or `key` (Ed25519) |
| `private-key` | When mode=key | | Ed25519 private key PEM |
| `key-id` | No | auto-derived | Key identifier |
| `skill-name` | Yes | | Skill name for attestation |
| `skill-version` | Yes | | Skill version for attestation |
| `skill-type` | No | `skill.md` | `skill.md` or `mcp` |
| `cosign` | No | `false` | Co-sign existing envelope |

## Outputs

| Output | Description |
|--------|-------------|
| `key-id` | Key ID or Sigstore identity that signed |
| `attestation-hash` | SHA-256 hash of the attestation |

## Verification

After signing, consumers verify with:

```bash
# Keyless verification
haldir verify ./my-skill --keyless \
  --trusted-identity "https://token.actions.githubusercontent.com=https://github.com/org/repo"

# Ed25519 verification
haldir verify ./my-skill --key publisher.pub
```
