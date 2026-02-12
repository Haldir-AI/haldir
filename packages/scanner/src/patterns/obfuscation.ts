import type { ThreatPattern } from './types.js';
import { CODE_EXTENSIONS } from '../types.js';

export const obfuscationPatterns: ThreatPattern[] = [
  {
    id: 'base64_api_key',
    category: 'obfuscation',
    severity: 'high',
    name: 'Base64-encoded API key pattern',
    description: 'Suspicious base64 string matching API key patterns',
    // Detects base64 strings that decode to "sk_", "AKIA", "Bearer ", etc.
    regex: /(?:atob|Buffer\.from|base64)\s*\(\s*['"`]([A-Za-z0-9+/=]{20,})['"`]\s*\)/,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'string_concat_secret',
    category: 'obfuscation',
    severity: 'medium',
    name: 'String concatenation with secret patterns',
    description: 'String concatenation forming API key or token patterns',
    // Detects: "sk_" + something, "api_key" + "=", etc.
    regex: /['"`](sk_|api[_-]?key|secret|token|bearer|auth)[_-]?['"`]\s*\+\s*['"`]/i,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'hex_escape_secret',
    category: 'obfuscation',
    severity: 'medium',
    name: 'Hex escape sequences',
    description: 'Excessive hex escape sequences possibly hiding secrets',
    // Detects strings with 8+ consecutive hex escapes (e.g., "\x73\x6b\x5f...")
    regex: /(?:\\x[0-9a-fA-F]{2}){8,}/,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'char_code_obfuscation',
    category: 'obfuscation',
    severity: 'medium',
    name: 'Character code obfuscation',
    description: 'Using fromCharCode to construct strings (possible secret hiding)',
    regex: /String\.fromCharCode\s*\([^)]{20,}\)/,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'template_literal_concat',
    category: 'obfuscation',
    severity: 'low',
    name: 'Template literal key construction',
    description: 'Template literals combining secret-like patterns',
    regex: /`[^`]*\$\{[^}]+\}[^`]*(key|secret|token|auth)[^`]*`/i,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'rot13_caesar',
    category: 'obfuscation',
    severity: 'medium',
    name: 'ROT13 or Caesar cipher usage',
    description: 'Simple character rotation possibly hiding credentials',
    regex: /(?:rot13|caesar|shift|rotate|decode|decipher)\s*\(/i,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'unicode_escape',
    category: 'obfuscation',
    severity: 'medium',
    name: 'Unicode escape obfuscation',
    description: 'Excessive unicode escapes possibly hiding secrets',
    // Detects strings with 6+ consecutive unicode escapes
    regex: /(?:\\u[0-9a-fA-F]{4}){6,}/,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'eval_exec_obfuscation',
    category: 'obfuscation',
    severity: 'critical',
    name: 'Dynamic code execution with encoding',
    description: 'eval() or Function() with base64/hex patterns',
    regex: /(?:eval|Function|setTimeout|setInterval)\s*\([^)]*(?:atob|base64|\\x[0-9a-f]{2})/i,
    fileExtensions: CODE_EXTENSIONS,
  },
  {
    id: 'split_reverse_join',
    category: 'obfuscation',
    severity: 'low',
    name: 'String reversal obfuscation',
    description: 'Reversing strings to hide patterns (e.g., "yek_ipa".reverse())',
    regex: /['"`][a-zA-Z0-9_-]{8,}['"`]\s*\.\s*(?:split|reverse|join)/,
    fileExtensions: CODE_EXTENSIONS,
  },
];
