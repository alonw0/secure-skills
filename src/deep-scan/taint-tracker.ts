import type { FileExtraction, TaintFlow, Source } from './types.ts';

/**
 * Single forward-pass taint propagation.
 * Tracks which variables are tainted (carry data from a Source),
 * then checks if any tainted variable reaches a Sink.
 */
export function trackTaintFlows(extraction: FileExtraction): TaintFlow[] {
  const taintMap = new Map<string, Source>();
  const chainParent = new Map<string, string>();

  // 1. Seed taint from sources
  for (const source of extraction.sources) {
    taintMap.set(source.variable, source);
  }

  // Build a function lookup
  const funcMap = new Map(extraction.functions.map((f) => [f.name, f]));

  // 2. Process assignments in line order — propagate taint forward
  const sortedAssignments = [...extraction.assignments].sort((a, b) => a.line - b.line);

  for (const assign of sortedAssignments) {
    for (const src of assign.sources) {
      if (taintMap.has(src)) {
        taintMap.set(assign.target, taintMap.get(src)!);
        chainParent.set(assign.target, src);
        break;
      }
    }
  }

  // 3. Intra-file function call propagation
  const sortedCalls = [...extraction.calls].sort((a, b) => a.line - b.line);

  for (const call of sortedCalls) {
    const funcDef = funcMap.get(call.callee);
    if (!funcDef) continue;

    // Propagate taint from args to params
    for (let i = 0; i < call.args.length && i < funcDef.params.length; i++) {
      const arg = call.args[i]!;
      if (taintMap.has(arg)) {
        const param = funcDef.params[i]!;
        taintMap.set(param, taintMap.get(arg)!);
        chainParent.set(param, arg);
      }
    }

    // If function returns a tainted variable, taint the call target
    if (call.target) {
      for (const retVar of funcDef.returnVars) {
        if (taintMap.has(retVar)) {
          taintMap.set(call.target, taintMap.get(retVar)!);
          chainParent.set(call.target, retVar);
          break;
        }
      }
    }
  }

  // 4. Detect flows: check if any sink variable is tainted
  const flows: TaintFlow[] = [];

  for (const sink of extraction.sinks) {
    for (const v of sink.variables) {
      if (taintMap.has(v)) {
        const chain = reconstructChain(v, chainParent, taintMap);
        flows.push({ source: taintMap.get(v)!, sink, chain });
        break; // One flow per sink
      }
    }
  }

  return flows;
}

/** Walk chainParent pointers to reconstruct the taint chain. */
function reconstructChain(
  variable: string,
  chainParent: Map<string, string>,
  taintMap: Map<string, Source>
): string[] {
  const chain: string[] = [];
  let current: string | undefined = variable;
  const seen = new Set<string>();

  while (current && !seen.has(current)) {
    seen.add(current);
    chain.unshift(current);
    current = chainParent.get(current);
  }

  // Prepend the source variable if not already in chain
  const source = taintMap.get(variable);
  if (source && chain[0] !== source.variable) {
    chain.unshift(source.variable);
  }

  return chain;
}
