import * as core from '@actions/core';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  createEnvelope,
  createKeylessEnvelope,
  appendSignature,
  deriveKeyId,
  hashData,
} from '@haldir/core';

async function run(): Promise<void> {
  try {
    const skillDir = core.getInput('skill-dir', { required: true });
    const mode = core.getInput('mode') || 'keyless';
    const skillName = core.getInput('skill-name', { required: true });
    const skillVersion = core.getInput('skill-version', { required: true });
    const skillType = core.getInput('skill-type') || 'skill.md';
    const cosign = core.getInput('cosign') === 'true';

    const skill = { name: skillName, version: skillVersion, type: skillType };

    if (cosign) {
      const privateKey = core.getInput('private-key', { required: true });
      core.setSecret(privateKey);
      const keyId = deriveKeyId(privateKey);
      await appendSignature(skillDir, privateKey);
      core.setOutput('key-id', keyId);
      core.info(`Co-signed ${skillDir} with key ${keyId}`);
    } else if (mode === 'keyless') {
      // GitHub Actions provides OIDC token automatically via ACTIONS_ID_TOKEN_REQUEST_URL
      const idToken = await core.getIDToken('sigstore');

      await createKeylessEnvelope(skillDir, {
        skill,
        identityToken: idToken,
      });

      core.setOutput('key-id', `sigstore:${process.env.GITHUB_ACTOR}`);
      core.info(`Signed ${skillDir} with Sigstore (keyless)`);
    } else if (mode === 'key') {
      const privateKey = core.getInput('private-key', { required: true });
      core.setSecret(privateKey);
      const keyId = core.getInput('key-id') || deriveKeyId(privateKey);

      await createEnvelope(skillDir, privateKey, { keyId, skill });

      core.setOutput('key-id', keyId);
      core.info(`Signed ${skillDir} with Ed25519 key ${keyId}`);
    } else {
      core.setFailed(`Unknown mode: ${mode}. Use "keyless" or "key".`);
      return;
    }

    // Output attestation hash
    const attestationPath = join(skillDir, '.vault', 'attestation.json');
    const attestationBytes = await readFile(attestationPath);
    const hash = hashData(attestationBytes);
    core.setOutput('attestation-hash', hash);
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
}

run();
