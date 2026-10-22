import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
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
      'packages/cli',
    ],
  },
});
