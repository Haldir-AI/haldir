/**
 * Lightweight package.json structural validator
 *
 * Catches supply chain risks that regex patterns miss:
 * - Unpinned/wildcard dependency versions
 * - Git URL dependencies
 * - Protocol smuggling (file://, etc.)
 * - Native addon install scripts (node-gyp)
 */

import type { Finding, Severity, ThreatCategory } from './types.js';

interface PackageJson {
  name?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface ManifestCheck {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  name: string;
  description: string;
  check: (pkg: PackageJson, filePath: string) => Finding[];
}

const WILDCARD_VERSIONS = ['*', 'latest', 'x', ''];

// Top npm packages — used for typosquat detection via edit distance.
// Intentionally limited to high-value targets that attackers actually typosquat.
const POPULAR_PACKAGES = [
  'express', 'react', 'lodash', 'axios', 'chalk', 'commander', 'debug',
  'dotenv', 'webpack', 'typescript', 'eslint', 'prettier', 'jest', 'mocha',
  'mongoose', 'sequelize', 'redis', 'moment', 'dayjs', 'uuid', 'cors',
  'helmet', 'passport', 'jsonwebtoken', 'bcrypt', 'nodemon', 'pm2',
  'next', 'nuxt', 'vue', 'angular', 'svelte', 'fastify', 'koa', 'hapi',
  'socket.io', 'graphql', 'prisma', 'knex', 'pg', 'mysql2', 'mongodb',
  'aws-sdk', 'firebase', 'stripe', 'twilio', 'nodemailer', 'puppeteer',
  'cheerio', 'sharp', 'jimp', 'multer', 'formidable', 'zod', 'yup', 'joi',
  'rxjs', 'ramda', 'underscore', 'async', 'bluebird', 'glob', 'minimatch',
  'semver', 'yargs', 'inquirer', 'ora', 'chalk', 'boxen', 'figlet',
  'fs-extra', 'rimraf', 'mkdirp', 'cross-env', 'concurrently', 'husky',
  'lint-staged', 'tsup', 'esbuild', 'vite', 'rollup', 'parcel', 'babel',
  'tailwindcss', 'postcss', 'sass', 'less', 'styled-components', 'emotion',
];

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

const manifestChecks: ManifestCheck[] = [
  {
    id: 'manifest_unpinned_deps',
    category: 'supply_chain',
    severity: 'medium',
    name: 'Unpinned dependency versions',
    description: 'Dependencies with wildcard or unpinned versions allow arbitrary upgrades',
    check(pkg, filePath) {
      const findings: Finding[] = [];
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.optionalDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        if (WILDCARD_VERSIONS.includes(version) || version.startsWith('>=')) {
          findings.push({
            pattern_id: 'manifest_unpinned_deps',
            category: 'supply_chain',
            severity: 'medium',
            file: filePath,
            line: 0,
            column: 0,
            match: `"${name}": "${version}"`,
            context: `Unpinned dependency: ${name}@${version}`,
            message: `Dependency "${name}" uses unpinned version "${version}" — allows arbitrary version resolution`,
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'manifest_git_url_dep',
    category: 'supply_chain',
    severity: 'high',
    name: 'Git URL dependency',
    description: 'Dependencies fetched from git URLs bypass registry integrity checks',
    check(pkg, filePath) {
      const findings: Finding[] = [];
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.optionalDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        if (/^git(\+https?|\+ssh)?:\/\//.test(version) || /^github:/.test(version)) {
          findings.push({
            pattern_id: 'manifest_git_url_dep',
            category: 'supply_chain',
            severity: 'high',
            file: filePath,
            line: 0,
            column: 0,
            match: `"${name}": "${version}"`,
            context: `Git URL dependency: ${name}`,
            message: `Dependency "${name}" uses git URL "${version}" — bypasses registry integrity checks`,
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'manifest_protocol_dep',
    category: 'supply_chain',
    severity: 'high',
    name: 'Non-registry protocol dependency',
    description: 'Dependencies using file://, http://, or other protocols bypass registry security',
    check(pkg, filePath) {
      const findings: Finding[] = [];
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.optionalDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        if (/^(file|http):\/\//.test(version)) {
          findings.push({
            pattern_id: 'manifest_protocol_dep',
            category: 'supply_chain',
            severity: 'high',
            file: filePath,
            line: 0,
            column: 0,
            match: `"${name}": "${version}"`,
            context: `Protocol dependency: ${name}`,
            message: `Dependency "${name}" uses protocol "${version}" — bypasses npm registry`,
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'manifest_native_addon',
    category: 'supply_chain',
    severity: 'high',
    name: 'Native addon build script',
    description: 'Install scripts that compile native code can execute arbitrary build commands',
    check(pkg, filePath) {
      const findings: Finding[] = [];
      const scripts = pkg.scripts ?? {};

      for (const [hook, cmd] of Object.entries(scripts)) {
        if (['install', 'preinstall', 'postinstall'].includes(hook)) {
          if (/node-gyp|cmake|make\b|gcc|g\+\+|clang/.test(cmd)) {
            findings.push({
              pattern_id: 'manifest_native_addon',
              category: 'supply_chain',
              severity: 'high',
              file: filePath,
              line: 0,
              column: 0,
              match: `"${hook}": "${cmd}"`,
              context: `Native build in ${hook} script`,
              message: `Install hook "${hook}" compiles native code: "${cmd}" — executes arbitrary build commands`,
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'manifest_typosquat',
    category: 'supply_chain',
    severity: 'high',
    name: 'Potential typosquat dependency',
    description: 'Dependency name is suspiciously close to a popular package (edit distance 1-2)',
    check(pkg, filePath) {
      const findings: Finding[] = [];
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.optionalDependencies,
      };

      for (const depName of Object.keys(allDeps)) {
        if (POPULAR_PACKAGES.includes(depName)) continue;
        for (const popular of POPULAR_PACKAGES) {
          const dist = levenshtein(depName, popular);
          if (dist > 0 && dist <= 2 && depName.length >= 3) {
            findings.push({
              pattern_id: 'manifest_typosquat',
              category: 'supply_chain',
              severity: 'high',
              file: filePath,
              line: 0,
              column: 0,
              match: `"${depName}"`,
              context: `Possible typosquat of "${popular}" (edit distance: ${dist})`,
              message: `Dependency "${depName}" is suspiciously similar to popular package "${popular}" (distance: ${dist})`,
            });
            break;
          }
        }
      }
      return findings;
    },
  },
];

export function scanManifest(content: string, filePath: string): Finding[] {
  let pkg: PackageJson;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }

  if (typeof pkg !== 'object' || pkg === null) return [];

  const findings: Finding[] = [];
  for (const check of manifestChecks) {
    findings.push(...check.check(pkg, filePath));
  }
  return findings;
}
