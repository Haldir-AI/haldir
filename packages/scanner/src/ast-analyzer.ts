import ts from 'typescript';
import type { ASTFinding, ASTRecommendation, ThreatCategory, Severity } from './types.js';

const EXEC_METHODS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync']);

export function analyzeFileAST(
  content: string,
  filePath: string,
  extension: string,
): ASTFinding[] {
  if (!['js', 'ts', 'jsx', 'tsx'].includes(extension)) return [];

  let sourceFile: ts.SourceFile;
  try {
    const scriptKind = extension === 'tsx' ? ts.ScriptKind.TSX
      : extension === 'jsx' ? ts.ScriptKind.JSX
      : extension === 'ts' ? ts.ScriptKind.TS
      : ts.ScriptKind.JS;

    sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true, scriptKind);
  } catch {
    return [];
  }

  const findings: ASTFinding[] = [];
  visitNode(sourceFile, filePath, findings);
  return findings;
}

function visitNode(node: ts.Node, filePath: string, findings: ASTFinding[]): void {
  if (ts.isCallExpression(node)) {
    checkCallExpression(node, filePath, findings);
  }
  if (ts.isNewExpression(node)) {
    checkNewExpression(node, filePath, findings);
  }
  ts.forEachChild(node, child => visitNode(child, filePath, findings));
}

function checkCallExpression(node: ts.CallExpression, filePath: string, findings: ASTFinding[]): void {
  // eval(x)
  if (ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
    const arg = node.arguments[0];
    if (arg && !isLiteral(arg)) {
      findings.push(makeFinding(node, arg, filePath, {
        pattern_id: 'ast_eval_non_literal',
        category: 'supply_chain',
        severity: 'critical',
        match: 'eval(...)',
        message: 'eval() with non-literal argument allows arbitrary code execution',
      }));
    }
    return;
  }

  // child_process.exec(x), execSync(x), spawn(x)
  if (ts.isPropertyAccessExpression(node.expression)) {
    const method = node.expression.name.text;
    if (EXEC_METHODS.has(method)) {
      const arg = node.arguments[0];
      if (arg && !isLiteral(arg)) {
        findings.push(makeFinding(node, arg, filePath, {
          pattern_id: 'ast_exec_non_literal',
          category: 'privilege_escalation',
          severity: 'critical',
          match: `${method}(...)`,
          message: `${method}() with non-literal argument may execute arbitrary commands`,
        }));
      }
      return;
    }
  }

  // Bare exec/execSync/spawn calls (destructured imports)
  if (ts.isIdentifier(node.expression) && EXEC_METHODS.has(node.expression.text)) {
    const arg = node.arguments[0];
    if (arg && !isLiteral(arg)) {
      findings.push(makeFinding(node, arg, filePath, {
        pattern_id: 'ast_exec_non_literal',
        category: 'privilege_escalation',
        severity: 'critical',
        match: `${node.expression.text}(...)`,
        message: `${node.expression.text}() with non-literal argument may execute arbitrary commands`,
      }));
    }
    return;
  }

  // Indirect execution: obj[dynamicKey]()
  if (ts.isElementAccessExpression(node.expression)) {
    const arg = node.expression.argumentExpression;
    if (!isLiteral(arg)) {
      findings.push(makeFinding(node, arg, filePath, {
        pattern_id: 'ast_indirect_execution',
        category: 'obfuscation',
        severity: 'high',
        match: '[computed]()',
        message: 'Computed property call allows indirect code execution',
      }));
    }
    return;
  }

  // Dynamic import: import(variable)
  if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
    const arg = node.arguments[0];
    if (arg && !isLiteral(arg)) {
      findings.push(makeFinding(node, arg, filePath, {
        pattern_id: 'ast_dynamic_import',
        category: 'supply_chain',
        severity: 'high',
        match: 'import(...)',
        message: 'Dynamic import() with non-literal specifier enables module loading attacks',
      }));
    }
    return;
  }
}

function checkNewExpression(node: ts.NewExpression, filePath: string, findings: ASTFinding[]): void {
  // new Function(x)
  if (ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
    const args = node.arguments;
    if (args && args.length > 0) {
      const bodyArg = args[args.length - 1];
      if (!isLiteral(bodyArg)) {
        findings.push(makeFinding(node, bodyArg, filePath, {
          pattern_id: 'ast_function_constructor',
          category: 'supply_chain',
          severity: 'critical',
          match: 'new Function(...)',
          message: 'Function constructor with non-literal argument allows code injection',
        }));
      }
    }
  }
}

function isLiteral(node: ts.Node): boolean {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node);
}

function getArgumentTypeName(node: ts.Node): string {
  if (ts.isIdentifier(node)) return 'Identifier';
  if (ts.isPropertyAccessExpression(node)) return 'MemberExpression';
  if (ts.isElementAccessExpression(node)) return 'ComputedMember';
  if (ts.isTemplateExpression(node)) return 'TemplateLiteral';
  if (ts.isCallExpression(node)) return 'CallExpression';
  if (ts.isBinaryExpression(node)) return 'BinaryExpression';
  if (ts.isConditionalExpression(node)) return 'ConditionalExpression';
  return node.kind.toString();
}

function scoreConfidence(argType: string): number {
  switch (argType) {
    case 'Identifier': return 0.95;
    case 'MemberExpression': return 0.90;
    case 'ComputedMember': return 0.92;
    case 'TemplateLiteral': return 0.88;
    case 'CallExpression': return 0.85;
    case 'BinaryExpression': return 0.82;
    case 'ConditionalExpression': return 0.80;
    default: return 0.70;
  }
}

function confidenceToRecommendation(confidence: number): ASTRecommendation {
  if (confidence >= 0.9) return 'block';
  if (confidence >= 0.7) return 'flag';
  if (confidence >= 0.5) return 'review';
  return 'pass';
}

function makeFinding(
  node: ts.Node,
  argNode: ts.Node,
  filePath: string,
  base: { pattern_id: string; category: ThreatCategory; severity: Severity; match: string; message: string },
): ASTFinding {
  const sourceFile = node.getSourceFile();
  const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
  const lineText = sourceFile.text.split('\n')[line] || '';
  const argType = getArgumentTypeName(argNode);
  const confidence = scoreConfidence(argType);

  return {
    ...base,
    file: filePath,
    line: line + 1,
    column: character,
    context: lineText.trim(),
    ast_node_type: ts.SyntaxKind[node.kind],
    argument_type: argType,
    confidence,
    recommendation: confidenceToRecommendation(confidence),
  };
}
