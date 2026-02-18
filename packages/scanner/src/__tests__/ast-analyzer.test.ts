import { describe, it, expect } from 'vitest';
import { analyzeFileAST } from '../ast-analyzer.js';
import type { ASTFinding } from '../types.js';

function analyze(code: string, ext = 'ts'): ASTFinding[] {
  return analyzeFileAST(code, `test.${ext}`, ext);
}

describe('analyzeFileAST', () => {
  describe('eval patterns', () => {
    it('flags eval(variable)', () => {
      const findings = analyze('const x = input; eval(x);');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_eval_non_literal');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].argument_type).toBe('Identifier');
    });

    it('skips eval("literal")', () => {
      const findings = analyze('eval("console.log(1)");');
      expect(findings).toHaveLength(0);
    });

    it('flags eval(obj.prop)', () => {
      const findings = analyze('eval(config.code);');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('MemberExpression');
      expect(findings[0].confidence).toBe(0.90);
    });

    it('flags eval(fn())', () => {
      const findings = analyze('eval(getCode());');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('CallExpression');
      expect(findings[0].confidence).toBe(0.85);
    });

    it('flags eval(template literal with expression)', () => {
      const findings = analyze('const x = "rm"; eval(`${x} -rf /`);');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('TemplateLiteral');
      expect(findings[0].confidence).toBe(0.88);
    });

    it('skips eval with no-substitution template literal', () => {
      const findings = analyze('eval(`console.log(1)`);');
      expect(findings).toHaveLength(0);
    });
  });

  describe('Function constructor', () => {
    it('flags new Function(variable)', () => {
      const findings = analyze('const fn = new Function(body);');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_function_constructor');
      expect(findings[0].severity).toBe('critical');
    });

    it('skips new Function("return 1")', () => {
      const findings = analyze('const fn = new Function("return 1");');
      expect(findings).toHaveLength(0);
    });

    it('flags new Function with multiple args where body is non-literal', () => {
      const findings = analyze('new Function("a", "b", bodyCode);');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('Identifier');
    });

    it('skips new Function with all literal args', () => {
      const findings = analyze('new Function("a", "return a + 1");');
      expect(findings).toHaveLength(0);
    });
  });

  describe('child_process patterns', () => {
    it('flags exec(variable) via property access', () => {
      const findings = analyze('const cp = require("child_process"); cp.exec(cmd);');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_exec_non_literal');
      expect(findings[0].severity).toBe('critical');
    });

    it('flags execSync with template literal', () => {
      const findings = analyze('import { execSync } from "child_process"; execSync(`ls ${dir}`);');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('TemplateLiteral');
    });

    it('skips execSync("ls")', () => {
      const findings = analyze('import { execSync } from "child_process"; execSync("ls -la");');
      expect(findings).toHaveLength(0);
    });

    it('flags spawn(variable, args)', () => {
      const findings = analyze('import { spawn } from "child_process"; spawn(cmd, args);');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_exec_non_literal');
    });

    it('flags execFile with non-literal', () => {
      const findings = analyze('child.execFile(binary, []);');
      expect(findings).toHaveLength(1);
    });

    it('flags spawnSync with non-literal', () => {
      const findings = analyze('child.spawnSync(command);');
      expect(findings).toHaveLength(1);
    });
  });

  describe('indirect execution', () => {
    it('flags obj[dynamicKey]()', () => {
      const findings = analyze('const key = "exec"; global[key]();');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_indirect_execution');
      expect(findings[0].severity).toBe('high');
    });

    it('flags this[method]()', () => {
      const findings = analyze('const m = getMethod(); this[m]();');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_indirect_execution');
    });

    it('skips obj["literal"]()', () => {
      const findings = analyze('obj["knownMethod"]();');
      expect(findings).toHaveLength(0);
    });

    it('flags window[computed]()', () => {
      const findings = analyze('const fn = name; window[fn]();');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('Identifier');
    });
  });

  describe('dynamic import', () => {
    it('flags import(variable)', () => {
      const findings = analyze('const mod = await import(modulePath);');
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_dynamic_import');
      expect(findings[0].severity).toBe('high');
    });

    it('skips import("./module")', () => {
      const findings = analyze('const mod = await import("./utils");');
      expect(findings).toHaveLength(0);
    });

    it('flags import(concatenation)', () => {
      const findings = analyze('const mod = await import("./plugins/" + name);');
      expect(findings).toHaveLength(1);
      expect(findings[0].argument_type).toBe('BinaryExpression');
      expect(findings[0].confidence).toBe(0.82);
    });
  });

  describe('confidence scoring', () => {
    it('Identifier argument scores 0.95', () => {
      const findings = analyze('eval(x);');
      expect(findings[0].confidence).toBe(0.95);
    });

    it('MemberExpression scores 0.90', () => {
      const findings = analyze('eval(obj.code);');
      expect(findings[0].confidence).toBe(0.90);
    });

    it('TemplateLiteral scores 0.88', () => {
      const findings = analyze('eval(`${code}`);');
      expect(findings[0].confidence).toBe(0.88);
    });

    it('CallExpression scores 0.85', () => {
      const findings = analyze('eval(getCode());');
      expect(findings[0].confidence).toBe(0.85);
    });

    it('BinaryExpression scores 0.82', () => {
      const findings = analyze('eval("prefix" + suffix);');
      expect(findings[0].confidence).toBe(0.82);
    });

    it('literal arguments produce no finding', () => {
      const findings = analyze('eval("safe"); execSync("ls"); import("./mod");');
      expect(findings).toHaveLength(0);
    });
  });

  describe('recommendation mapping', () => {
    it('confidence >= 0.9 maps to block', () => {
      const findings = analyze('eval(x);');
      expect(findings[0].confidence).toBe(0.95);
      expect(findings[0].recommendation).toBe('block');
    });

    it('confidence >= 0.7 and < 0.9 maps to flag', () => {
      const findings = analyze('eval("prefix" + suffix);');
      expect(findings[0].confidence).toBe(0.82);
      expect(findings[0].recommendation).toBe('flag');
    });

    it('high severity indirect execution with Identifier is block', () => {
      const findings = analyze('global[key]();');
      expect(findings[0].confidence).toBe(0.95);
      expect(findings[0].recommendation).toBe('block');
    });
  });

  describe('edge cases', () => {
    it('returns empty for non-JS/TS extensions', () => {
      const findings = analyzeFileAST('eval(x)', 'test.py', 'py');
      expect(findings).toHaveLength(0);
    });

    it('returns empty for unparseable code', () => {
      const findings = analyze('}{}{}{invalid syntax that still parses somehow');
      // TypeScript parser is very lenient; this may or may not produce findings
      // Key thing: it should NOT throw
      expect(Array.isArray(findings)).toBe(true);
    });

    it('handles JSX files', () => {
      const findings = analyzeFileAST(
        'function App() { eval(code); return <div />; }',
        'App.tsx',
        'tsx',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].pattern_id).toBe('ast_eval_non_literal');
    });

    it('handles JS files', () => {
      const findings = analyzeFileAST('eval(x)', 'test.js', 'js');
      expect(findings).toHaveLength(1);
    });

    it('reports correct line numbers', () => {
      const findings = analyze('const a = 1;\nconst b = 2;\neval(x);\n');
      expect(findings).toHaveLength(1);
      expect(findings[0].line).toBe(3);
    });

    it('includes context from the source line', () => {
      const findings = analyze('  eval(userInput);');
      expect(findings[0].context).toBe('eval(userInput);');
    });

    it('reports ast_node_type for findings', () => {
      const findings = analyze('eval(x);');
      expect(findings[0].ast_node_type).toBe('CallExpression');
    });

    it('reports ast_node_type for new expressions', () => {
      const findings = analyze('new Function(body);');
      expect(findings[0].ast_node_type).toBe('NewExpression');
    });
  });

  describe('multiple findings per file', () => {
    it('detects multiple distinct patterns', () => {
      const code = `
        eval(x);
        new Function(body);
        global[key]();
        import(modulePath);
      `;
      const findings = analyze(code);
      const ids = findings.map(f => f.pattern_id);
      expect(ids).toContain('ast_eval_non_literal');
      expect(ids).toContain('ast_function_constructor');
      expect(ids).toContain('ast_indirect_execution');
      expect(ids).toContain('ast_dynamic_import');
      expect(findings.length).toBe(4);
    });
  });
});
