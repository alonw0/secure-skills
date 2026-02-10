import type { ScanFinding, ScanSeverity } from '../scanner.ts';
import type { TaintFlow } from './types.ts';
import { analyzePythonFile } from './python-analyzer.ts';
import { analyzeJsFile } from './js-analyzer.ts';
import { trackTaintFlows } from './taint-tracker.ts';
import { detectCrossFileFlows } from './cross-file.ts';

/**
 * Run deep taint analysis on all files. Returns ScanFinding[] compatible
 * with the existing scanner output.
 */
export function deepScanFiles(files: Map<string, string>): ScanFinding[] {
  const extractions = new Map<string, import('./types.ts').FileExtraction>();

  // 1. Extract structure from each file
  for (const [fileName, content] of files) {
    if (fileName.endsWith('.py')) {
      extractions.set(fileName, analyzePythonFile(fileName, content));
    } else if (/\.(js|ts|mjs|cjs)$/.test(fileName)) {
      extractions.set(fileName, analyzeJsFile(fileName, content));
    }
  }

  if (extractions.size === 0) return [];

  // 2. Intra-file taint tracking
  const allFlows: TaintFlow[] = [];
  for (const extraction of extractions.values()) {
    allFlows.push(...trackTaintFlows(extraction));
  }

  // 3. Cross-file analysis
  allFlows.push(...detectCrossFileFlows(extractions));

  // 4. Convert to ScanFindings
  return allFlows.map(flowToFinding);
}

function flowToFinding(flow: TaintFlow): ScanFinding {
  const isCrossFile = flow.chain.includes('<cross-file>');
  const prefix = isCrossFile ? 'deep-cross' : 'deep';
  const rule = `${prefix}-${flow.source.kind}-to-${flow.sink.kind}`;
  const severity = deriveSeverity(flow, isCrossFile);
  const chainStr = flow.chain.join(' → ');

  const message = isCrossFile
    ? `Cross-file taint flow: ${flow.source.kind} in ${flow.source.file}:${flow.source.line} → ${flow.sink.kind} in ${flow.sink.file}:${flow.sink.line}`
    : `Taint flow: ${flow.source.kind} → ${flow.sink.kind} via [${chainStr}]`;

  return {
    rule,
    severity,
    message,
    file: flow.sink.file,
    line: flow.sink.line,
    matchedText:
      flow.sink.rawText.length > 120 ? flow.sink.rawText.slice(0, 117) + '...' : flow.sink.rawText,
  };
}

function deriveSeverity(flow: TaintFlow, isCrossFile: boolean): ScanSeverity {
  if (isCrossFile) return 'critical';

  const { kind: srcKind } = flow.source;
  const { kind: sinkKind } = flow.sink;

  if (
    (srcKind === 'env-access' || srcKind === 'credential-file') &&
    (sinkKind === 'network' || sinkKind === 'exec')
  ) {
    return 'critical';
  }
  if (srcKind === 'file-read' && sinkKind === 'network') return 'high';
  if (srcKind === 'getattr-trick') return 'high';
  if (srcKind === 'function-param' && (sinkKind === 'exec' || sinkKind === 'network')) {
    return 'medium';
  }
  return 'high';
}
