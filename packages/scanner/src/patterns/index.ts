import { exfiltrationPatterns } from './exfiltration.js';
import { privilegePatterns } from './privilege.js';
import { supplyChainPatterns } from './supply-chain.js';
import { promptInjectionPatterns } from './prompt-injection.js';
import { persistencePatterns } from './persistence.js';
import { campaignPatterns } from './campaign.js';
import { credentialPatterns } from './credentials.js';
import type { ThreatPattern } from './types.js';

export const PATTERN_DB: readonly ThreatPattern[] = Object.freeze([
  ...exfiltrationPatterns,
  ...privilegePatterns,
  ...supplyChainPatterns,
  ...promptInjectionPatterns,
  ...persistencePatterns,
  ...campaignPatterns,
  ...credentialPatterns,
]);
