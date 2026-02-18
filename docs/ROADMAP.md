# Haldir — Complete Forward Plan

**Status:** Phases 1, 2A, 2B, 2C, 2D, 2E, 3 (core) complete. This document covers remaining work.

**Last updated:** 2026-02-15

---

## Current State

```
Phase 1: Crypto Foundation ✅ DONE
├── 11 packages (@haldir/core, cli, sdk, scanner, auditor, sandbox, reviewer, pipeline, enforcer, registry, scheduler)
├── .vault/ envelope format (DSSE v1.0.0, RFC 8785, Ed25519, SHA-256)
├── V1 Verification Contract (25 checks, fail-fast)
├── Revocation lists (signed, install fail-closed / runtime fail-open)
├── CLI (keygen, sign, verify, inspect, revoke, test)
├── SDK (Haldir class, structured trust levels)
├── 3 rounds security hardening applied
└── Open spec: ASAF v1.0-draft (haldir/docs/SPEC.md)

Phase 2A: Sigstore Keyless Signing ✅ DONE
├── signWithSigstore() / verifyWithSigstore() in @haldir/core
├── createKeylessEnvelope() — OIDC-based signing (no private key files)
├── verifySigstoreEnvelope() — full verification contract for Sigstore bundles
├── Auto-detect: verify CLI auto-selects Ed25519 or Sigstore path
├── --keyless / --identity-token flags on sign + verify CLI
├── Trusted identity pinning (--trusted-identity issuer=subject)
└── Ed25519 retained as offline fallback

Phase 2C: Dual-Sign ✅ DONE
├── appendSignature() — add co-signature to existing .vault/
├── haldir cosign <dir> --key <path> CLI command
├── Multi-sig verification (any matching key wins)
└── Duplicate keyId rejection

SDK: Sigstore support ✅ DONE
├── verifySigstore() — Sigstore-specific verification
├── autoVerify() — auto-detect Ed25519 or Sigstore
├── trustedIdentities + revocationKeys config
└── 8 SDK tests (4 Ed25519 + 4 Sigstore)

GitHub Action: haldir-ai/sign-action ✅ DONE
├── Keyless signing (Sigstore OIDC — zero secrets needed)
├── Ed25519 key signing (with GitHub secret)
├── Co-signing support
└── Bundled with @vercel/ncc (1.1MB)

Phase 2B-Layer1: Static Analysis Scanner ✅ DONE
├── @haldir/scanner package (standalone, no @haldir/core dependency)
├── 70 threat patterns across 7 categories
│   ├── Exfiltration (env harvest, fs enumerate, data exfil, context leakage)
│   ├── Privilege escalation (sudo, credential access, docker socket, /proc)
│   ├── Supply chain (curl|sh, obfuscated exec, base64 pipe, unpinned deps)
│   ├── Prompt injection (instruction override, hidden Unicode, persona override)
│   ├── Persistence (reverse shell, memory poison, cron, startup scripts)
│   ├── Campaign indicators (paste service, URL shortener, C2 channels)
│   └── Credential exposure (AWS, OpenAI, Stripe, GitHub, PEM keys, JWT)
├── scanDirectory() → ScanResult (pass/flag/reject + findings)
├── haldir scan <dir> CLI command (--json, --severity, --strict)
├── Extension-based pattern filtering for performance
└── 91 scanner tests (patterns, matcher, file-reader, engine)

Phase 2B-Layer2: Dependency Auditor ✅ DONE
├── @haldir/auditor package (standalone)
├── Manifest parsing: package.json, requirements.txt, pyproject.toml
├── Pin validation: flags ^/~/>=/* ranges, exact + hash pinning
├── Lock file checks: package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lockb
├── Dependency count limits: >20 for skill.md, >50 for MCP
├── Depth analysis: flags transitive trees >5 levels
├── PEP 723 deferred dependency attack detection (critical severity)
├── Suspicious package checks: git deps, install hooks, wildcard versions
├── npm advisory API integration (optional CVE lookup)
├── haldir audit <dir> CLI command (--json, --type, --no-cve)
└── 80 auditor tests (parsers, checks, engine)

Phase 2B-Layer3: Sandbox Execution ✅ DONE
├── @haldir/sandbox package
├── Subprocess runner with timeout, memory limits, safe env
├── Permissions.json → sandbox config translation
├── Entrypoint auto-detection (Node, Python, shell)
├── Output analyzer: detects network, exec, filesystem violations
├── Compares runtime behavior against declared permissions
├── haldir sandbox <dir> CLI command (--json, --timeout, --entrypoint)
└── 51 sandbox tests (permissions, detect, runner, analyzer, engine)

Phase 2B-Layer4: LLM Semantic Audit ✅ DONE
├── @haldir/reviewer package
├── Dual-model parallel review with configurable providers
├── OpenAI-compatible + Anthropic API adapters
├── 5 weighted review questions (description, directives, permissions, exfil, quality)
├── Auto-approve (>0.95), auto-reject (<0.70), amber zone (human review)
├── Disagreement detection with escalation to third model
├── Skill content collector (code files, SKILL.md, permissions)
├── haldir review <dir> CLI command (--provider, --json)
└── 35 reviewer tests (prompt, engine with mocked providers, collect)

Phase 2B-Pipeline: Vetting Orchestrator ✅ DONE
├── @haldir/pipeline package — ties all layers together
├── vetSkill() → PipelineResult (approved/rejected/amber/error)
├── Sequential execution: scan → audit → sandbox → review
├── Fail-fast: reject at first critical finding (configurable)
├── Skip layers: skipLayers config for partial pipeline runs
└── 10 pipeline integration tests

Phase 2B-Transparency: Vetting Report Disclosure ✅ DONE
├── vetting-report.json in .vault/ (optional transparency disclosure)
├── Hash-bound to attestation (vetting_report_hash prevents tampering)
├── Canonical JSON (RFC 8785) for deterministic hashing
├── Schema validation with size limits (DoS protection)
├── 5-layer findings, overall status (pass/flag/reject), publisher note
├── --vetting-report <path> flag on haldir sign + cosign
├── Returned in verify result even on signature failure
├── Timestamp validation (vetting before signing, staleness warnings)
└── 10/10 security score (hash-binding, canonical JSON, size limits)

Phase 2D: Runtime Permission Enforcement ✅ DONE
├── @haldir/enforcer package
├── Permission compiler (permissions.json → sandbox policy)
├── Node.js --allow-fs-read/write enforcement
├── macOS sandbox-exec profiles
├── haldir enforce <dir> CLI command
└── 12 enforcer tests (compiler, runner, node-permissions, darwin-sandbox)

Phase 2E: Registry API ✅ DONE
├── @haldir/registry package (Express v5, MemoryStore)
├── Skill submission, search, download endpoints
├── Publisher trust tiers (unverified/verified/trusted/internal)
├── API key authentication with timing-safe comparison
├── Revocation + advisory endpoints
├── Pattern bundle endpoint (dynamic scanner updates)
├── Federation badge + verify endpoints
└── 81 registry tests (store, server, tiers, auth, patterns)

Phase 3 (Core): Rescan + Federation ✅ DONE
├── @haldir/scheduler — tier-based rescan policies (7d/14d/30d/on-update)
├── Federation badge + verify endpoints
├── Dynamic pattern updates from registry (24h cache + fallback)
└── 28 scheduler tests

687 tests passing across 44 test files, 11 packages
```

### What's Still Missing

- No public key / identity distribution mechanism
- No revocation list hosting
- ~~No registry API~~ — @haldir/registry built (Express v5, tiers, auth, patterns) ✅
- ~~No vetting pipeline~~ — 5-layer pipeline built (Layers 1-4 + orchestrator) ✅
- ~~No vetting transparency~~ — hash-bound vetting-report.json complete ✅
- ~~No permission enforcement~~ — @haldir/enforcer built (Node.js + macOS sandbox) ✅
- No publisher identity or accounts
- ~~No CI/CD integration~~ — GitHub Action built (action/) ✅
- No human review dashboard (Layer 5)
- No submission queue (Redis/Celery)
- No npm packages published yet

---

## Phase 1.5 — Ship What We Have (1-2 days)

Make Phase 1 usable before building more.

| Task | Why | Effort |
|------|-----|--------|
| Write `haldir/README.md` | Nobody knows what this is or how to use it | 2h |
| Complete doc renames (ClawVault → Haldir) | 6 files still reference old name | 1h |
| Document Phase 1 trust model | Who signs, who verifies, how keys distributed | 1h |
| Publish npm packages | @haldir/core, @haldir/cli, @haldir/sdk | 2h |
| Push `haldir-ai/spec` repo | ASAF spec (Apache 2.0) — establishes the standard | 1h |
| Push `haldir-ai/haldir` repo | Reference implementation | 1h |

### Phase 1 Trust Model (honest)

```
Publisher signs their own skills with their own Ed25519 key
  → distributes .pub key out-of-band (manual)
  → consumer verifies with that key
  → no central authority yet
```

### Doc Renames ✅ DONE

All ClawVault → Haldir renames completed across 6 files.

---

## Phase 2A — Authority Infrastructure + Sigstore ✅ DONE

Establishes HydraCore as the trusted authority for skill signing using **Sigstore keyless signing** — the industry standard for open source projects (used by npm, PyPI, Kubernetes).

### Why Sigstore (Not KMS/Vault)

| Option | Cost | Complexity | Right for OSS? |
|--------|------|-----------|----------------|
| AWS KMS | ~$1/mo per key | High (AWS account, IAM, vendor lock) | No |
| HashiCorp Vault | Free self-host, BSL license | High (ops burden, not truly OSS since 2023) | No |
| Flat key file | Free | Low but risky (key theft = game over) | Temporary only |
| **Sigstore** | **Free (public good)** | **Medium (integration work)** | **Yes** |

Sigstore eliminates key management entirely:
- No private key files to protect, rotate, or back up
- Identity-based: sign as your GitHub/OIDC identity
- Transparency log (Rekor): every signature publicly auditable, free
- Used by npm, PyPI, Kubernetes, Homebrew — battle-tested

### How It Works

```
Publisher authenticates via OIDC (GitHub, Google)
  → Sigstore Fulcio issues 10-minute ephemeral certificate
  → Publisher signs with ephemeral key (key only exists in memory)
  → Rekor appends signature to public transparency log
  → signatures[].keyid = OIDC subject (e.g. "github:alice")
  → Verifier checks Rekor inclusion proof + certificate chain
  → No private key ever touches disk
```

### Transitional Key Strategy

While Sigstore integration is built, use a transitional approach:

```
Phase 1.5 (now):      Maintainer Ed25519 key (encrypted, backed up offline)
                       GitHub Actions secret for CI signing
Phase 2A (this):      Sigstore keyless signing (replaces key files)
                       Rekor transparency log (free, public)
                       Ed25519 still supported for offline/air-gapped use
```

### Revocation Infrastructure

Revocation key remains Ed25519 (revocation lists need to work offline):

```
haldir-revoke-prod     → Signs revocation lists
haldir-revoke-staging  → Signs during testing
```

| Detail | Value |
|--------|-------|
| Endpoint | `https://haldir.ai/.well-known/haldir-revocation.json` |
| CDN | Cloudflare Pages or GitHub Pages (free for OSS) |
| TTL | 30 minutes |
| Sync | HydraEye heartbeat pulls latest list |
| Key storage | GitHub Actions secret (CI) + encrypted offline backup |
| Format | Already implemented in Phase 1 |

### Public Key / Identity Distribution

| Channel | Purpose |
|---------|---------|
| Bundled in @haldir/sdk | Default trusted OIDC identities + revocation pubkey |
| `https://haldir.ai/.well-known/haldir-keys.json` | Web-accessible (GitHub Pages, free) |
| Rekor transparency log | Public audit trail for all signatures |
| Pinned in HydraEye agent config | All managed VPS instances |

### Signing Service

```
CI Pipeline (GitHub Actions):
  on skill submission → vet → sign via Sigstore → publish to CDN

Manual (offline/emergency):
  haldir sign <dir> --key haldir-revoke.key   → Ed25519 fallback

Revocation:
  haldir revoke <name@ver> --key revoke.key   → Sign + publish to CDN
```

### Deliverables

- [x] Sigstore Fulcio integration in @haldir/core
- [x] Rekor transparency log integration
- [x] Signature verification against Fulcio certificate chain
- [x] OIDC identity in signatures[].keyid (sigstore:<identity> format)
- [x] Ed25519 retained as offline fallback
- [x] Auto-detect: CLI verify picks Ed25519 or Sigstore automatically
- [x] Trusted identity pinning (--trusted-identity issuer=subject)
- [ ] Revocation key: encrypted offline backup + GitHub Actions secret (ops)
- [ ] Revocation list hosting (GitHub Pages / Cloudflare Pages — free) (ops)
- [ ] Public key / identity distribution endpoint (ops)

---

## Phase 2B — Vetting Pipeline (4-6 weeks)

The reason consumers should trust HydraCore's signature. A signature from us means "this passed our vetting."

### 5-Layer Pipeline

```
Submission → Queue → [Layer 1-5] → Sign or Reject → Publish

Layer 1: Static Analysis (<1s)
├── 171 regex patterns (prompt injection, credential theft, exec injection)
├── SKILL.md + MCP code content scanning
├── Auto-reject: credentials, eval/exec, dangerous patterns
└── Auto-flag: minor violations, edge cases

Layer 2: Dependency Audit (5-15s)
├── All deps pinned + hash-locked?
├── CVE cross-reference (npm advisory, Snyk, GitHub Advisory)
├── Flag: deep dependency trees (>5 levels), high counts (>20 SKILL.md, >50 MCP)
└── PEP 723 deferred dependency attack detection

Layer 3: Sandbox Execution (30-90s)
├── gVisor or Firecracker isolation
├── For SKILL.md: simulate agent loading, invoke declared commands
├── For MCP: install deps, start server, call tools
├── Monitor: syscalls, filesystem access, network connections
└── Compare actual behavior vs. declared permissions.json

Layer 4: LLM Semantic Audit (10-30s)
├── Dual-model: DeepSeek v3 + Kimi K2.5 (parallel)
├── Questions: matches description? hidden directives? permission minimal? exfil risk?
├── Scores: 0.0 (malicious) to 1.0 (benign)
├── Both >0.95 → auto-approve
├── Either <0.70 → auto-reject
├── Between 0.70-0.95 → amber queue (human review)
└── Disagreement (|diff| > 0.2) → escalate to Claude Sonnet

Layer 5: Human Review (amber zone only)
├── Manual review + approval/rejection/request changes
└── Appeal process for auto-rejected skills
```

### After Vetting Passes

1. HydraCore signs the skill with `haldir-signing-prod` key
2. Attestation includes vetting results + trust score (0.0-1.0)
3. Published to registry CDN
4. Indexed for search

### Cost Model

| Scale | Monthly Cost | Dominant Cost |
|-------|-------------|---------------|
| MVP (internal skills) | ~$250/mo | Infrastructure |
| 100 submissions/day | ~$600/mo | LLM audit |
| 500 submissions/day | ~$1,310/mo | LLM audit ($750/mo) |

### Deliverables

- [ ] Submission queue (Redis/Celery)
- [x] Layer 1: Static analysis engine (70 patterns, @haldir/scanner)
- [x] Layer 2: Dependency auditor (@haldir/auditor)
- [x] Layer 3: Sandbox execution (@haldir/sandbox)
- [x] Layer 4: Dual-LLM audit integration (@haldir/reviewer)
- [x] Pipeline orchestrator (@haldir/pipeline)
- [x] Vetting report transparency (hash-bound vetting-report.json)
- [ ] Layer 5: Human review dashboard
- [ ] Vetting result storage (PostgreSQL)
- [ ] Auto-sign on approval
- [ ] CDN publish pipeline

---

## Phase 2C — Dual-Sign ✅ DONE

Publisher signs (proves authorship) + HydraCore co-signs (proves vetting passed).

### Signature Format

```json
{
  "signatures": [
    {
      "keyid": "publisher-alice-2026",
      "sig": "<publisher's Ed25519 signature>"
    },
    {
      "keyid": "haldir-signing-prod-2026",
      "sig": "<HydraCore's Ed25519 signature>"
    }
  ]
}
```

### Flow

```
Publisher:
  1. haldir keygen (once)
  2. haldir sign my-skill/ --key my.key
  3. Submit to registry: POST /v1/submit (includes .vault/ with publisher sig)

HydraCore:
  4. Vetting pipeline runs (5 layers)
  5. If passes → HydraCore co-signs (adds second entry to signatures[])
  6. Published skill has both signatures

Consumer:
  7. haldir verify my-skill/ --key haldir-prod.pub
  8. Trusts HydraCore's key → doesn't need to know publisher keys
  9. Can ALSO verify publisher key if they want direct trust
```

### Key Benefit

Consumers only need to trust ONE key (HydraCore's). HydraCore's signature means "we vetted this." Publisher's signature provides provenance and accountability.

### Deliverables

- [x] `appendSignature()` — appends co-signature to existing .vault/signature.json
- [x] `haldir cosign <dir> --key <path>` CLI command
- [x] Multi-sig verification (any matching key wins — Phase 1 foundation)
- [x] Duplicate keyId rejection
- [x] 9 dual-sign tests (sign → co-sign → verify with either key)
- [ ] Co-signing API endpoint (Phase 2E — registry)
- [ ] Publisher key registration in registry (Phase 2E)

---

## Phase 2D — Runtime Permission Enforcement ✅ DONE

Permissions.json is now enforced at runtime via @haldir/enforcer.

### Current vs. Target

```
Phase 1: permissions.json = "I promise I only read /data/"  (informational)
Phase 2: Runtime enforces  = "You WILL only read /data/"    (enforced)
```

### Enforcement Mechanism

| Permission | Enforcement |
|------------|------------|
| `filesystem.read` | Restrict read to declared paths only |
| `filesystem.write` | Restrict write to declared paths only |
| `network` | Block all network unless declared endpoints |
| `exec` | Block subprocess spawning unless declared |
| `agent_capabilities.memory_read` | Gate access to Mnemo read APIs |
| `agent_capabilities.memory_write` | Gate access to Mnemo write APIs |
| `agent_capabilities.spawn_agents` | Block agent spawning unless declared |
| `agent_capabilities.modify_system_prompt` | Block prompt modification unless declared |

### Implementation

- Linux: seccomp-bpf (syscall filtering)
- macOS: sandbox profiles (sandbox-exec)
- Backup: Node.js --experimental-permission flag (limited but portable)
- Integration point: HydraCore agent runtime skill loader

### Integration with Agent Runtime

```
Agent loads skill →
  1. Haldir verify (signature + integrity)     ✅ Phase 1
  2. Check revocation list                      ✅ Phase 1
  3. Parse permissions.json                     🆕 Phase 2D
  4. Create sandbox with declared permissions   🆕 Phase 2D
  5. Execute skill within sandbox               🆕 Phase 2D
  6. Any violation → kill skill + alert         🆕 Phase 2D
```

### Deliverables

- [x] Permission parser (permissions.json → sandbox policy)
- [ ] Linux sandbox (seccomp-bpf / Landlock — pending validation)
- [x] macOS sandbox (sandbox profiles)
- [x] Node.js --allow-fs-read/write enforcement
- [x] haldir enforce CLI command
- [ ] Agent runtime integration
- [ ] Violation detection + alerting
- [ ] Audit logging (every grant/deny)

---

## Phase 2E — Registry API ✅ DONE (core)

Registry API built with Express v5, MemoryStore (PostgreSQL-ready).

### Core Endpoints

```
POST   /v1/submit                      # Submit skill for vetting
GET    /v1/status/:submission_id       # Check vetting status
GET    /v1/skills/:name                # Skill metadata + versions
GET    /v1/skills/:name/:version       # Specific version
GET    /v1/skills/:name/download       # Download skill package + .vault/
GET    /v1/revocations                 # Current signed revocation list
GET    /v1/search?q=&type=&agent=      # Search registry
POST   /v1/verify                      # Verify a .vault/ remotely
GET    /v1/publishers/:id              # Publisher profile
GET    /v1/advisories                  # Security advisories
GET    /v1/advisories/:id              # Specific advisory
```

### Well-Known Endpoints

```
GET /.well-known/haldir-keys.json          # Current public keys
GET /.well-known/haldir-revocation.json    # Current revocation list
```

### Publisher Trust Tiers

```
Unverified (default)
├── Any GitHub/email account
├── Full 5-layer vetting for every submission
└── No badge

Verified (earned)
├── 5+ approved skills, zero rejections, 90-day track record
├── ✓ badge
├── Layers 1-2 + LLM audit for updates (skip full sandbox)
└── One revoked skill → drops back to Unverified

Trusted (invitation-only)
├── Major OSS contributors, known organizations
├── ★ badge
├── Layers 1-2 only for updates
└── Periodic full re-audit (quarterly)

HydraCore (internal)
├── ⬡ badge
├── Internal review process
└── First-party skills
```

### Frontend: vault.hydracore.dev

- Search and browse skills
- Publisher profiles with trust badges
- Vetting scores and permission declarations
- Install instructions for LaunchClaw/Doppel
- Security advisory feed

### Deliverables

- [x] API server (Express v5, MemoryStore — PostgreSQL-ready)
- [x] Authentication (API keys with timing-safe comparison)
- [x] Publisher trust tiers (unverified/verified/trusted/internal)
- [x] Pattern bundle endpoint (dynamic scanner updates)
- [x] Federation badge + verify endpoints
- [ ] PostgreSQL schema (skills, publishers, submissions, vetting_results)
- [ ] GitHub OAuth
- [ ] CDN for skill packages
- [ ] Search index (PostgreSQL full-text or Meilisearch)
- [ ] Publisher onboarding flow
- [ ] Frontend (vault.hydracore.dev)
- [ ] Rate limiting, pagination, filtering

---

## Phase 3 — Ecosystem & Federation (8-12 weeks)

Sigstore is now in Phase 2A. Phase 3 focuses on ecosystem growth and federation.

### Federation

| Source | Action |
|--------|--------|
| skills.sh | Auto-import top skills, vet, sign, publish |
| MCP Registry | Auto-import popular servers |
| Smithery | Badge integration |

### GitHub Action: `haldir-ai/sign-action`

```yaml
# .github/workflows/sign.yml
- uses: haldir-ai/sign-action@v1
  with:
    skill-dir: ./my-skill
    # Keyless (Sigstore) or key-based
    key: ${{ secrets.HALDIR_PRIVATE_KEY }}  # optional if using Sigstore
```

### Additional Features

| Feature | Detail |
|---------|--------|
| Security advisories | CVE-like system for agent skills |
| Periodic rescans | Weekly (public), bi-weekly (verified), monthly (trusted) |
| CodeMarine integration | Pattern harvester feeds real-time threat intel |
| Transparency log | Every signature logged to Rekor |

### Deliverables

- [x] Sigstore Fulcio integration (done in Phase 2A)
- [x] Rekor transparency log integration (done in Phase 2A)
- [ ] Federation importers (skills.sh, MCP Registry)
- [x] `haldir-ai/sign-action` GitHub Action (action/ directory)
- [ ] Security advisory system
- [x] Periodic rescan pipeline (@haldir/scheduler — tier-based policies)
- [ ] CodeMarine webhook integration

---

## Phase 4 — Scale & Enterprise (6-8 weeks)

| Feature | Detail |
|---------|--------|
| Enterprise private registries | Org-scoped, custom vetting rules, namespace isolation |
| ML threat detection | Beyond regex — behavioral analysis, anomaly detection |
| Community threat intel | Users report suspicious skills, crowdsource patterns |
| Advisory database | Searchable, cross-referenced, automated notifications |
| Industry partnerships | CoSAI, OWASP, MCP spec authors |
| Compliance exports | SOC2, GDPR, HIPAA audit logs |
| Advanced analytics | Ecosystem health dashboard, trend detection |

---

## Platform Integration Points

### LaunchClaw

- Skills verified before install via Haldir
- User sees publisher tier + trust score in skill browser
- Install blocked if verification fails (fail-closed)

### Doppel

- All pre-configured packs use Haldir-signed skills only
- Enterprise customers can require specific trust tiers
- Turnkey security — no configuration needed

### HydraEye

- Reports installed skill versions + integrity hashes on heartbeat
- Auto-syncs revocation list from CDN
- Alerts on skill integrity failures
- Phase 2D: enforces permission sandbox

### Mnemo (Agent Memory)

- Skills can't poison AGENTS.md, SOUL.md (integrity hash detects)
- Memory access gated by permissions.json (Phase 2D)

### Agent Runtime

- Deny-by-default: HydraCore agents require valid .vault/
- Three-layer gate: Clawdex check → CodeMarine scan → Haldir verify
- Phase 2D adds fourth layer: permission enforcement sandbox

---

## Timeline

```
Feb 2026      Phase 1 ✅ Crypto Foundation
Feb 2026      Phase 1.5 — README ✅, doc renames ✅, repos pushed ✅
Feb 2026      Phase 2A — Sigstore keyless signing ✅
Feb 2026      Phase 2B — 5-layer vetting pipeline + transparency ✅
Feb 2026      Phase 2C — Dual-sign ✅
Feb 2026      Phase 2D — Runtime permission enforcement ✅
Feb 2026      Phase 2E — Registry API + publisher tiers ✅
Feb 2026      Phase 3 (core) — Scheduler + federation + dynamic patterns ✅
              -------------------------------------------------------
              npm publish, production keypair, revocation hosting
Mar-Apr 2026  Phase 3 (ecosystem) — Federation importers, advisories
Apr-May 2026  Phase 4 — Enterprise, ML, community intel
```

---

## Open Design Questions

1. ~~AWS KMS vs HashiCorp Vault~~ — **Resolved: Sigstore (free, OSS) for signing. Ed25519 retained for revocation + offline fallback.**
2. **Sandbox technology** — gVisor vs Firecracker vs Wasm for Layer 3 vetting
3. **Permission enforcement** — seccomp vs Node --experimental-permission vs custom
4. **Registry stack** — FastAPI (match HydraCore) vs Express (match Haldir ecosystem)
5. **LLM budget** — DeepSeek + Kimi confirmed, or evaluate alternatives?
6. ~~Sigstore timeline~~ — **Resolved: Pulled forward to Phase 2A.**
7. **Federation priority** — skills.sh first or MCP Registry first?
8. **Appeal process** — How do publishers contest auto-rejection?
9. **Revocation key backup** — Encrypted USB + printed seed? Or GitHub Actions secret only?

---

## Competitive Position

| Capability | Current | After Phase 2 | After Phase 3 | Competitors |
|------------|---------|---------------|---------------|-------------|
| Cryptographic signing | ✅ | ✅ | ✅ | Nobody |
| Signed revocation | ✅ | ✅ | ✅ | Nobody |
| Keyless signing (Sigstore) | ✅ | ✅ | ✅ | Nobody (for agent skills) |
| Transparency log (Rekor) | ✅ | ✅ | ✅ | Nobody (for agent skills) |
| Dual-sign | ✅ | ✅ | ✅ | Nobody |
| 5-layer vetting | ✅ | ✅ | ✅ | Nobody |
| Permission enforcement | ✅ | ✅ | ✅ | mcp.run (Wasm only) |
| Registry API | ✅ | ✅ | ✅ | Nobody (for agent skills) |
| Periodic rescans | ✅ | ✅ | ✅ | Nobody |
| Federation | ❌ | ❌ | ✅ | Nobody |
| Dual-LLM semantic audit | ✅ | ✅ | ✅ | Nobody |

**The moat:** Every phase adds a layer no competitor has. By Phase 3, Haldir is the most secure agent skill ecosystem in existence.
