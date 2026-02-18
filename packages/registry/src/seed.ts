import { PATTERN_DB, serializeBundle } from '@haldir/scanner';
import type { RegistryStore } from './store/types.js';

export async function seedBuiltinPatterns(store: RegistryStore): Promise<void> {
  const existing = await store.getPatternBundle('1.0.0');
  if (existing) return;
  const bundle = serializeBundle('1.0.0', PATTERN_DB);
  await store.addPatternBundle(bundle);
}
