import type {
  FileExtraction,
  Source,
  Sink,
  Assignment,
  FunctionDef,
  CallSite,
  ImportInfo,
} from './types.ts';

const PYTHON_KEYWORDS = new Set([
  'False',
  'None',
  'True',
  'and',
  'as',
  'assert',
  'async',
  'await',
  'break',
  'class',
  'continue',
  'def',
  'del',
  'elif',
  'else',
  'except',
  'finally',
  'for',
  'from',
  'global',
  'if',
  'import',
  'in',
  'is',
  'lambda',
  'nonlocal',
  'not',
  'or',
  'pass',
  'raise',
  'return',
  'try',
  'while',
  'with',
  'yield',
]);

/** Join continuation lines (backslash + unbalanced parens/brackets). */
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
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
    }

    if (line.endsWith('\\')) {
      buffer = buffer.slice(0, -1);
      continue;
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
    } else if (ch === '#') {
      break;
    } else if (ch === '"' || ch === "'") {
      if (line.slice(i, i + 3) === ch.repeat(3)) {
        const end = line.indexOf(ch.repeat(3), i + 3);
        if (end !== -1) {
          result += line.slice(i, end + 3);
          i = end + 2;
        } else {
          result += ch;
          inStr = ch;
          i += 2;
        }
      } else {
        result += ch;
        inStr = ch;
      }
    } else {
      result += ch;
    }
  }
  return result;
}

/** Strip comments AND string literal contents to avoid false variable extraction from strings. */
function stripStringsAndComments(line: string): string {
  let result = '';
  let inStr: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inStr) {
      if (ch === inStr && line[i - 1] !== '\\') inStr = null;
      result += ' ';
    } else if (ch === '#') {
      break;
    } else if (ch === '"' || ch === "'") {
      if (line.slice(i, i + 3) === ch.repeat(3)) {
        const end = line.indexOf(ch.repeat(3), i + 3);
        if (end !== -1) {
          result += ' '.repeat(end + 3 - i);
          i = end + 2;
        } else {
          result += ' ';
          inStr = ch;
          i += 2;
        }
      } else {
        inStr = ch;
        result += ' ';
      }
    } else {
      result += ch;
    }
  }
  return result;
}

/** Extract identifiers from a code fragment, filtering out Python keywords. */
function extractVars(text: string): string[] {
  const ids = text.match(/\b([a-zA-Z_]\w*)\b/g) || [];
  return ids.filter((id) => !PYTHON_KEYWORDS.has(id));
}

export function analyzePythonFile(fileName: string, content: string): FileExtraction {
  const rawLines = content.split('\n');
  const joined = joinContinuationLines(rawLines);
  const sources: Source[] = [];
  const sinks: Sink[] = [];
  const assignments: Assignment[] = [];
  const functions: FunctionDef[] = [];
  const calls: CallSite[] = [];
  const imports: ImportInfo[] = [];

  // Track current function scope for return analysis
  let currentFunc: { name: string; params: string[]; line: number; returnVars: string[] } | null =
    null;

  for (const { text, origLine } of joined) {
    const commentStripped = stripComments(text);
    const stripped = stripStringsAndComments(text);
    const lineNum = origLine + 1;

    // ── Functions ──────────────────────────────────────────────────────────
    const funcMatch = stripped.match(/^(\s*)def\s+(\w+)\s*\((.*?)\)\s*:/);
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
      const params = funcMatch[3]!
        .split(',')
        .map((p) => p.trim().split(/[=:]/)[0]!.trim())
        .filter((p) => p && p !== 'self' && p !== 'cls');
      currentFunc = { name: funcMatch[2]!, params, line: lineNum, returnVars: [] };
    }

    // ── Returns (for current function) ────────────────────────────────────
    if (currentFunc) {
      const retMatch = stripped.match(/\breturn\s+(\w+)/);
      if (retMatch) currentFunc.returnVars.push(retMatch[1]!);
    }

    // ── Sources ───────────────────────────────────────────────────────────
    const sourcePatterns: [RegExp, Source['kind']][] = [
      [/(\w+)\s*=\s*os\.environ\.copy\s*\(/, 'env-access'],
      [/(\w+)\s*=\s*os\.environ\.get\s*\(/, 'env-access'],
      [/(\w+)\s*=\s*os\.environ\s*\[/, 'env-access'],
      [/(\w+)\s*=\s*os\.environ\b/, 'env-access'],
      [/(\w+)\s*=\s*os\.getenv\s*\(/, 'env-access'],
      [
        /(\w+)\s*=\s*open\s*\(.*(?:\.aws|\.ssh|\.gnupg|\.env\b|credentials|\.netrc)/,
        'credential-file',
      ],
      [/(\w+)\s*=\s*getattr\s*\(\s*\w+\s*,\s*['"](?:environ|system|popen)['"]/, 'getattr-trick'],
      [/(\w+)\s*=\s*open\s*\(.*\)\.read/, 'file-read'],
      [/(\w+)\s*=\s*(?:pathlib\.)?Path\s*\(.*\)\.read_text\s*\(/, 'file-read'],
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
        break; // Only one source per line (patterns ordered most-specific first)
      }
    }

    // ── Sinks ─────────────────────────────────────────────────────────────
    const sinkPatterns: [RegExp, Sink['kind']][] = [
      [/requests\.(?:post|put|get|delete)\s*\((.*)/, 'network'],
      [/urllib[23]?\.request\.(?:urlopen|Request)\s*\((.*)/, 'network'],
      [/http\.client\.HTTP.*\.(?:request|send)\s*\((.*)/, 'network'],
      [/socket\..*?\.(?:send|connect)\s*\((.*)/, 'network'],
      [/subprocess\.(?:run|call|Popen|check_output)\s*\((.*)/, 'exec'],
      [/os\.(?:system|popen)\s*\((.*)/, 'exec'],
      [/(?:^|[^.\w])(?:exec|eval)\s*\((.*)/, 'exec'],
      [/open\s*\(.*['"](?:w|a|wb|ab)['"].*\)\.write\s*\((.*)/, 'file-write'],
    ];

    for (const [pattern, kind] of sinkPatterns) {
      const m = commentStripped.match(pattern);
      if (m) {
        const vars = extractVars(m[1] || '');
        sinks.push({ kind, variables: vars, file: fileName, line: lineNum, rawText: text.trim() });
      }
    }

    // ── Assignments ───────────────────────────────────────────────────────
    const assignMatch = stripped.match(/^(\s*)(\w+)\s*=\s*(.+)/);
    if (assignMatch && !stripped.match(/^(\s*)def\s/) && !stripped.match(/^(\s*)class\s/)) {
      const target = assignMatch[2]!;
      const rhs = assignMatch[3]!;
      const rhsVars = extractVars(rhs);
      if (rhsVars.length > 0) {
        assignments.push({ target, sources: rhsVars, file: fileName, line: lineNum });
      }
    }

    // ── Call sites ────────────────────────────────────────────────────────
    const callMatch = stripped.match(/(?:(\w+)\s*=\s*)?(\w+)\s*\(([^)]*)\)/);
    if (callMatch && !stripped.match(/^\s*def\s/) && !stripped.match(/^\s*class\s/)) {
      const callee = callMatch[2]!;
      if (!PYTHON_KEYWORDS.has(callee)) {
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
    const importFromMatch = stripped.match(/from\s+(\S+)\s+import\s+(.+)/);
    if (importFromMatch) {
      const names = importFromMatch[2]!
        .split(',')
        .map((n) =>
          n
            .trim()
            .split(/\s+as\s+/)[0]!
            .trim()
        )
        .filter(Boolean);
      imports.push({ fromFile: fileName, module: importFromMatch[1]!, names, line: lineNum });
    } else {
      const importMatch = stripped.match(/^import\s+(\S+)/);
      if (importMatch) {
        imports.push({
          fromFile: fileName,
          module: importMatch[1]!,
          names: [importMatch[1]!],
          line: lineNum,
        });
      }
    }
    const dynImportMatch = commentStripped.match(/(\w+)\s*=\s*__import__\s*\(['"](.+?)['"]\)/);
    if (dynImportMatch) {
      imports.push({
        fromFile: fileName,
        module: dynImportMatch[2]!,
        names: [dynImportMatch[1]!],
        line: lineNum,
      });
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
