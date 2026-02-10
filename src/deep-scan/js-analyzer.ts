import type {
  FileExtraction,
  Source,
  Sink,
  Assignment,
  FunctionDef,
  CallSite,
  ImportInfo,
} from './types.ts';

const JS_KEYWORDS = new Set([
  'abstract',
  'arguments',
  'await',
  'boolean',
  'break',
  'byte',
  'case',
  'catch',
  'char',
  'class',
  'const',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'double',
  'else',
  'enum',
  'eval',
  'export',
  'extends',
  'false',
  'final',
  'finally',
  'float',
  'for',
  'function',
  'goto',
  'if',
  'implements',
  'import',
  'in',
  'instanceof',
  'int',
  'interface',
  'let',
  'long',
  'native',
  'new',
  'null',
  'of',
  'package',
  'private',
  'protected',
  'public',
  'return',
  'short',
  'static',
  'super',
  'switch',
  'synchronized',
  'this',
  'throw',
  'throws',
  'transient',
  'true',
  'try',
  'typeof',
  'undefined',
  'var',
  'void',
  'volatile',
  'while',
  'with',
  'yield',
]);

/** Join continuation lines — tracks bracket depth. */
function joinContinuationLines(lines: string[]): { text: string; origLine: number }[] {
  const result: { text: string; origLine: number }[] = [];
  let buffer = '';
  let startLine = 0;
  let depth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (buffer === '') startLine = i;
    buffer += (buffer ? ' ' : '') + line;

    for (const ch of line) {
      if (ch === '(' || ch === '[') depth++;
      else if (ch === ')' || ch === ']') depth = Math.max(0, depth - 1);
    }

    if (depth > 0) continue;

    result.push({ text: buffer, origLine: startLine });
    buffer = '';
  }
  if (buffer) result.push({ text: buffer, origLine: startLine });
  return result;
}

/** Strip only comments, keeping string contents intact. */
function stripComments(line: string): string {
  let result = '';
  let inStr: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inStr) {
      result += ch;
      if (ch === inStr && line[i - 1] !== '\\') inStr = null;
    } else if (ch === '/' && line[i + 1] === '/') {
      break;
    } else if (ch === '`' || ch === '"' || ch === "'") {
      result += ch;
      inStr = ch;
    } else {
      result += ch;
    }
  }
  return result;
}

/** Strip comments AND string contents to avoid false variable extraction. */
function stripStringsAndComments(line: string): string {
  let result = '';
  let inStr: string | null = null;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inStr) {
      if (ch === inStr && line[i - 1] !== '\\') inStr = null;
      result += ' ';
    } else if (ch === '/' && line[i + 1] === '/') {
      break;
    } else if (ch === '`' || ch === '"' || ch === "'") {
      inStr = ch;
      result += ' ';
    } else {
      result += ch;
    }
  }
  return result;
}

/** Extract identifiers from a code fragment, filtering out JS keywords. */
function extractVars(text: string): string[] {
  const ids = text.match(/\b([a-zA-Z_$]\w*)\b/g) || [];
  return ids.filter((id) => !JS_KEYWORDS.has(id));
}

export function analyzeJsFile(fileName: string, content: string): FileExtraction {
  const rawLines = content.split('\n');
  const joined = joinContinuationLines(rawLines);
  const sources: Source[] = [];
  const sinks: Sink[] = [];
  const assignments: Assignment[] = [];
  const functions: FunctionDef[] = [];
  const calls: CallSite[] = [];
  const imports: ImportInfo[] = [];

  let currentFunc: { name: string; params: string[]; line: number; returnVars: string[] } | null =
    null;

  for (const { text, origLine } of joined) {
    const commentStripped = stripComments(text);
    const stripped = stripStringsAndComments(text);
    const lineNum = origLine + 1;

    // ── Functions ──────────────────────────────────────────────────────────
    const funcMatch =
      stripped.match(/function\s+(\w+)\s*\((.*?)\)/) ||
      stripped.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|(\w+))\s*=>/);
    if (funcMatch) {
      if (currentFunc) {
        functions.push({
          name: currentFunc.name,
          params: currentFunc.params,
          file: fileName,
          line: currentFunc.line,
          returnVars: currentFunc.returnVars,
        });
      }
      const paramStr = funcMatch[2] || funcMatch[3] || '';
      const params = paramStr
        .split(',')
        .map((p) => p.trim().split(/[=:]/)[0]!.trim())
        .filter(Boolean);
      currentFunc = { name: funcMatch[1]!, params, line: lineNum, returnVars: [] };
    }

    // ── Returns ───────────────────────────────────────────────────────────
    if (currentFunc) {
      const retMatch = stripped.match(/\breturn\s+(\w+)/);
      if (retMatch) currentFunc.returnVars.push(retMatch[1]!);
    }

    // ── Sources ───────────────────────────────────────────────────────────
    const sourcePatterns: [RegExp, Source['kind']][] = [
      [/(\w+)\s*=\s*process\.env\.(\w+)/, 'env-access'],
      [/(\w+)\s*=\s*process\.env\s*\[/, 'env-access'],
      [/(\w+)\s*=\s*process\.env\b/, 'env-access'],
      [
        /(\w+)\s*=\s*(?:Object\.(?:keys|values|entries)\s*\(\s*process\.env|JSON\.stringify\s*\(\s*process\.env)/,
        'env-access',
      ],
      [
        /(\w+)\s*=\s*(?:fs\.readFileSync|readFileSync)\s*\(.*(?:\.aws|\.ssh|\.env\b|credentials)/,
        'credential-file',
      ],
      [/(\w+)\s*=\s*(?:fs\.readFileSync|readFileSync)\s*\(/, 'file-read'],
    ];

    for (const [pattern, kind] of sourcePatterns) {
      const m = commentStripped.match(pattern);
      if (m) {
        sources.push({
          kind,
          variable: m[1]!,
          file: fileName,
          line: lineNum,
          rawText: text.trim(),
        });
        break; // Only one source per line
      }
    }

    // ── Sinks ─────────────────────────────────────────────────────────────
    const sinkPatterns: [RegExp, Sink['kind']][] = [
      [/fetch\s*\((.*)/, 'network'],
      [/axios(?:\.(?:post|put|get|delete))?\s*\((.*)/, 'network'],
      [/https?\.request\s*\((.*)/, 'network'],
      [/child_process\.(?:exec|execSync|spawn|spawnSync)\s*\((.*)/, 'exec'],
      [/(?:^|[^.\w])(?:eval|Function)\s*\((.*)/, 'exec'],
      [/(?:fs\.writeFileSync|writeFileSync|fs\.appendFileSync)\s*\((.*)/, 'file-write'],
    ];

    for (const [pattern, kind] of sinkPatterns) {
      const m = commentStripped.match(pattern);
      if (m) {
        const vars = extractVars(m[1] || '');
        sinks.push({ kind, variables: vars, file: fileName, line: lineNum, rawText: text.trim() });
      }
    }

    // ── Assignments ───────────────────────────────────────────────────────
    const declMatch = stripped.match(/(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|$)/);
    if (declMatch) {
      const rhsVars = extractVars(declMatch[2]!);
      if (rhsVars.length > 0) {
        assignments.push({
          target: declMatch[1]!,
          sources: rhsVars,
          file: fileName,
          line: lineNum,
        });
      }
    } else {
      const reassignMatch = stripped.match(/^\s*(\w+)\s*=\s*(.+?)(?:;|$)/);
      if (
        reassignMatch &&
        !stripped.match(/^\s*(?:function|class|if|for|while|switch|import|export)\s/)
      ) {
        const rhsVars = extractVars(reassignMatch[2]!);
        if (rhsVars.length > 0) {
          assignments.push({
            target: reassignMatch[1]!,
            sources: rhsVars,
            file: fileName,
            line: lineNum,
          });
        }
      }
    }

    // ── Call sites ────────────────────────────────────────────────────────
    const callMatch = stripped.match(/(?:(?:const|let|var)\s+(\w+)\s*=\s*)?(\w+)\s*\(([^)]*)\)/);
    if (
      callMatch &&
      !stripped.match(/^\s*(?:function|class|if|for|while|switch)\s/) &&
      callMatch[2]
    ) {
      const callee = callMatch[2];
      if (!JS_KEYWORDS.has(callee)) {
        const args = extractVars(callMatch[3] || '');
        calls.push({
          callee,
          args,
          target: callMatch[1] || undefined,
          file: fileName,
          line: lineNum,
        });
      }
    }

    // ── Imports ───────────────────────────────────────────────────────────
    const esImportMatch = commentStripped.match(/import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/);
    if (esImportMatch) {
      const names = esImportMatch[1]!
        .split(',')
        .map((n) =>
          n
            .trim()
            .split(/\s+as\s+/)[0]!
            .trim()
        )
        .filter(Boolean);
      imports.push({ fromFile: fileName, module: esImportMatch[2]!, names, line: lineNum });
    }
    const nsImportMatch = commentStripped.match(
      /import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]/
    );
    if (nsImportMatch) {
      imports.push({
        fromFile: fileName,
        module: nsImportMatch[2]!,
        names: [nsImportMatch[1]!],
        line: lineNum,
      });
    }
    const defaultImportMatch = commentStripped.match(/import\s+(\w+)\s+from\s+['"]([^'"]+)['"]/);
    if (defaultImportMatch && !esImportMatch && !nsImportMatch) {
      imports.push({
        fromFile: fileName,
        module: defaultImportMatch[2]!,
        names: [defaultImportMatch[1]!],
        line: lineNum,
      });
    }
    const cjsMatch = commentStripped.match(
      /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(['"]([^'"]+)['"]\)/
    );
    if (cjsMatch) {
      imports.push({
        fromFile: fileName,
        module: cjsMatch[2]!,
        names: [cjsMatch[1]!],
        line: lineNum,
      });
    }
    const cjsDestructMatch = commentStripped.match(
      /(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(['"]([^'"]+)['"]\)/
    );
    if (cjsDestructMatch) {
      const names = cjsDestructMatch[1]!
        .split(',')
        .map((n) =>
          n
            .trim()
            .split(/\s*:\s*/)[0]!
            .trim()
        )
        .filter(Boolean);
      imports.push({ fromFile: fileName, module: cjsDestructMatch[2]!, names, line: lineNum });
    }
  }

  // Finalize last function
  if (currentFunc) {
    functions.push({
      name: currentFunc.name,
      params: currentFunc.params,
      file: fileName,
      line: currentFunc.line,
      returnVars: currentFunc.returnVars,
    });
  }

  return { file: fileName, sources, sinks, assignments, functions, calls, imports };
}
