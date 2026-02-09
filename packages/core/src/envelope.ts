import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalize, canonicalizeToBuffer } from './canonical.js';
import { encodePAE } from './pae.js';
import { sign as ed25519Sign, hashData, deriveKeyId, base64urlEncode } from './crypto.js';
import { checkFilesystem, hashDirectory } from './integrity.js';
import { VAULT_DIR, HALDIR_PAYLOAD_TYPE } from './types.js';
import type { EnvelopeOptions, SignatureEnvelope, Attestation, IntegrityManifest, Permissions } from './types.js';

export async function createEnvelope(
  skillDir: string,
  privateKeyPem: string,
  options: EnvelopeOptions
): Promise<void> {
  const fsCheck = await checkFilesystem(skillDir);
  if (!fsCheck.valid) {
    const msgs = fsCheck.errors.map((e) => `${e.code}: ${e.message}`).join('; ');
    throw new Error(`Filesystem check failed: ${msgs}`);
  }

  const vaultDir = join(skillDir, VAULT_DIR);
  await mkdir(vaultDir, { recursive: true });

  const files = await hashDirectory(skillDir);
  const integrityObj: IntegrityManifest = {
    schema_version: '1.0',
    algorithm: 'sha256',
    files,
    generated_at: new Date().toISOString(),
  };
  const integrityBytes = canonicalizeToBuffer(integrityObj);
  await writeFile(join(vaultDir, 'integrity.json'), integrityBytes);

  // Build permissions BEFORE attestation so we can hash it into the signed payload
  const permissionsObj: Permissions = {
    schema_version: '1.0',
    declared: options.permissions ?? {
      filesystem: { read: [], write: [] },
      network: 'none',
      exec: [],
      agent_capabilities: {
        memory_read: false,
        memory_write: false,
        spawn_agents: false,
        modify_system_prompt: false,
      },
    },
  };
  const permissionsCanonical = canonicalizeToBuffer(permissionsObj);
  const permissionsHash = hashData(permissionsCanonical);

  const integrityHash = hashData(integrityBytes);
  const attestationObj: Attestation = {
    schema_version: '1.0',
    skill: options.skill,
    integrity_hash: integrityHash,
    permissions_hash: permissionsHash,
    signed_at: new Date().toISOString(),
  };
  const attestationBytes = canonicalizeToBuffer(attestationObj);
  await writeFile(join(vaultDir, 'attestation.json'), attestationBytes);

  const paeBuffer = encodePAE(HALDIR_PAYLOAD_TYPE, attestationBytes);
  const signature = ed25519Sign(paeBuffer, privateKeyPem);

  const keyId = options.keyId ?? deriveKeyId(privateKeyPem);

  const signatureEnvelope: SignatureEnvelope = {
    schema_version: '1.0',
    payloadType: HALDIR_PAYLOAD_TYPE,
    payload: base64urlEncode(attestationBytes),
    signatures: [
      {
        keyid: keyId,
        sig: base64urlEncode(signature),
      },
    ],
  };
  await writeFile(
    join(vaultDir, 'signature.json'),
    JSON.stringify(signatureEnvelope, null, 2) + '\n'
  );

  // Write permissions as pretty JSON (human-readable).
  // Verification hashes canonical(parse(file)) — format doesn't matter.
  await writeFile(
    join(vaultDir, 'permissions.json'),
    JSON.stringify(permissionsObj, null, 2) + '\n'
  );
}
