import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
  'packages/core',
  'packages/sdk',
  'packages/scanner',
  'packages/auditor',
  'packages/sandbox',
  'packages/reviewer',
  'packages/pipeline',
  'packages/enforcer',
  'packages/registry',
  'packages/scheduler',
]);
