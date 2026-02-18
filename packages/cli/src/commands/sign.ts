import { readFile } from 'node:fs/promises';
import { createEnvelope, createKeylessEnvelope, deriveKeyId, VettingReportSchema } from '@haldir/core';
import type { VettingReport } from '@haldir/core';

interface SignOptions {
  key?: string;
  keyless?: boolean;
  identityToken?: string;
  name?: string;
  skillVersion?: string;
  type?: string;
  vettingReport?: string;
}

export async function signCommand(dir: string, opts: SignOptions): Promise<void> {
  const skill = {
    name: opts.name ?? 'unnamed',
    version: opts.skillVersion ?? '0.0.0',
    type: opts.type ?? 'skill.md',
  };

  // Parse optional vetting report
  let vettingReport: VettingReport | undefined;
  if (opts.vettingReport) {
    try {
      const vettingRaw = await readFile(opts.vettingReport, 'utf-8');
      const vettingParsed = JSON.parse(vettingRaw);
      const validated = VettingReportSchema.safeParse(vettingParsed);
      if (!validated.success) {
        console.error(`Error: invalid vetting report: ${validated.error.message}`);
        process.exit(2);
      }
      vettingReport = validated.data;
    } catch (err) {
      console.error(`Error reading vetting report: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(2);
    }
  }

  if (opts.keyless) {
    await createKeylessEnvelope(dir, {
      skill,
      identityToken: opts.identityToken,
      vettingReport,
    });

    console.log(`✓ Signed (keyless/Sigstore): ${dir}`);
    console.log(`Signature recorded in Rekor transparency log`);
    if (vettingReport) {
      console.log(`Vetting report included (status: ${vettingReport.overall_status})`);
    }
    return;
  }

  if (!opts.key) {
    console.error('Error: --key <path> is required (or use --keyless for Sigstore signing)');
    process.exit(2);
  }

  const privateKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(privateKey);

  await createEnvelope(dir, privateKey, {
    keyId,
    skill,
    vettingReport,
  });

  console.log(`✓ Signed: ${dir}`);
  console.log(`Key ID: ${keyId}`);
  if (vettingReport) {
    console.log(`Vetting report included (status: ${vettingReport.overall_status})`);
  }
}
