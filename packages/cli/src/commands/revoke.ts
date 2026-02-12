import { readFile, writeFile } from 'node:fs/promises';
import { createRevocationList, deriveKeyId, RevocationListSchema } from '@haldir/core';
import type { RevocationEntry, SignedRevocationList } from '@haldir/core';

interface RevokeOptions {
  key: string;
  list: string;
  reason: string;
  severity?: string;
}

export async function revokeCommand(nameAtVersion: string, opts: RevokeOptions): Promise<void> {
  const [name, version] = nameAtVersion.split('@');
  if (!name || !version) {
    console.error('Usage: haldir revoke <name@version>');
    process.exit(2);
  }

  const privateKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(privateKey);

  let existing: SignedRevocationList | undefined;
  try {
    const raw = await readFile(opts.list, 'utf-8');
    const parsed = JSON.parse(raw);
    const validated = RevocationListSchema.safeParse(parsed);
    if (!validated.success) {
      console.error(`Warning: existing revocation list is malformed, starting fresh`);
    } else {
      existing = validated.data as SignedRevocationList;
    }
  } catch {
    // new list
  }

  const entries: RevocationEntry[] = existing?.entries ? [...existing.entries] : [];
  entries.push({
    name,
    versions: [version],
    revoked_at: new Date().toISOString(),
    reason: opts.reason,
    severity: opts.severity ?? 'high',
  });

  const seqNum = existing ? existing.sequence_number + 1 : 1;
  const list = createRevocationList(entries, privateKey, keyId, seqNum);

  await writeFile(opts.list, JSON.stringify(list, null, 2) + '\n');
  console.log(`Revoked: ${name}@${version}`);
  console.log(`List: ${opts.list} (seq: ${seqNum})`);
}
