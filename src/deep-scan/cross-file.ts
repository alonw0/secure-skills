import type { FileExtraction, TaintFlow } from './types.ts';

/**
 * Detect cross-file taint flows based on import relationships.
 * Three patterns: env exfiltration, credential-network separation, env var exfiltration.
 */
export function detectCrossFileFlows(extractions: Map<string, FileExtraction>): TaintFlow[] {
  const flows: TaintFlow[] = [];

  // Build import adjacency: file → set of files it imports from
  const importEdges = new Map<string, Set<string>>();
  for (const [file, ext] of extractions) {
    const targets = new Set<string>();
    for (const imp of ext.imports) {
      const resolved = resolveImport(file, imp.module, [...extractions.keys()]);
      if (resolved) targets.add(resolved);
    }
    importEdges.set(file, targets);
  }

  /** Check if fileA and fileB are import-connected (either direction). */
  function areConnected(fileA: string, fileB: string): boolean {
    return (
      (importEdges.get(fileA)?.has(fileB) ?? false) || (importEdges.get(fileB)?.has(fileA) ?? false)
    );
  }

  const files = [...extractions.entries()];
  for (let i = 0; i < files.length; i++) {
    for (let j = i + 1; j < files.length; j++) {
      const [fileA, extA] = files[i]!;
      const [fileB, extB] = files[j]!;

      if (!areConnected(fileA, fileB)) continue;

      // Pattern A: env/credential sources in one file, network sinks in other
      emitCrossFlows(extA, extB, ['env-access', 'credential-file'], ['network'], flows);
      emitCrossFlows(extB, extA, ['env-access', 'credential-file'], ['network'], flows);

      // Pattern B: credential sources in one file, network sinks in other
      emitCrossFlows(extA, extB, ['credential-file'], ['network'], flows);
      emitCrossFlows(extB, extA, ['credential-file'], ['network'], flows);

      // Pattern C: env sources in one file, exec sinks in other
      emitCrossFlows(extA, extB, ['env-access'], ['exec'], flows);
      emitCrossFlows(extB, extA, ['env-access'], ['exec'], flows);
    }
  }

  return deduplicateFlows(flows);
}

function emitCrossFlows(
  sourceExt: FileExtraction,
  sinkExt: FileExtraction,
  sourceKinds: string[],
  sinkKinds: string[],
  flows: TaintFlow[]
): void {
  const matchingSources = sourceExt.sources.filter((s) => sourceKinds.includes(s.kind));
  const matchingSinks = sinkExt.sinks.filter((s) => sinkKinds.includes(s.kind));

  if (matchingSources.length > 0 && matchingSinks.length > 0) {
    // Emit one flow per source-sink pair (capped to avoid explosion)
    for (const source of matchingSources) {
      for (const sink of matchingSinks) {
        flows.push({ source, sink, chain: ['<cross-file>'] });
      }
    }
  }
}

/** Resolve a module specifier to a file in the extraction map. */
function resolveImport(fromFile: string, module: string, fileNames: string[]): string | undefined {
  // Only resolve relative imports
  if (!module.startsWith('.')) return undefined;

  // Normalize Python-style dot-relative imports:
  //   .module  → ./module
  //   ..module → ../module
  let normalized = module;
  const dotMatch = normalized.match(/^(\.+)(\w.*)$/);
  if (dotMatch) {
    const dots = dotMatch[1]!;
    const rest = dotMatch[2]!;
    if (dots === '.') normalized = './' + rest;
    else if (dots === '..') normalized = '../' + rest;
    else normalized = '../'.repeat(dots.length - 1) + rest;
  }

  // Get the directory of the importing file
  const parts = fromFile.split('/');
  parts.pop();
  const dir = parts.join('/');

  // Normalize the module path
  const segments = normalized.split('/');
  const resolved: string[] = dir ? dir.split('/') : [];
  for (const seg of segments) {
    if (seg === '.') continue;
    else if (seg === '..') resolved.pop();
    else resolved.push(seg);
  }
  const base = resolved.join('/');

  // Try candidate extensions
  const candidates = [
    base,
    base + '.py',
    base + '.js',
    base + '.ts',
    base + '/__init__.py',
    base + '/index.js',
    base + '/index.ts',
  ];

  for (const candidate of candidates) {
    if (fileNames.includes(candidate)) return candidate;
  }
  return undefined;
}

/** Remove duplicate flows (same source file+line, same sink file+line). */
function deduplicateFlows(flows: TaintFlow[]): TaintFlow[] {
  const seen = new Set<string>();
  return flows.filter((f) => {
    const key = `${f.source.file}:${f.source.line}->${f.sink.file}:${f.sink.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
