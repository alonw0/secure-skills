export type SourceKind =
  | 'env-access'
  | 'credential-file'
  | 'file-read'
  | 'function-param'
  | 'getattr-trick';
export type SinkKind = 'network' | 'exec' | 'file-write';

export interface Source {
  kind: SourceKind;
  variable: string;
  file: string;
  line: number;
  rawText: string;
}

export interface Sink {
  kind: SinkKind;
  variables: string[];
  file: string;
  line: number;
  rawText: string;
}

export interface Assignment {
  target: string;
  sources: string[];
  file: string;
  line: number;
}

export interface FunctionDef {
  name: string;
  params: string[];
  file: string;
  line: number;
  returnVars: string[];
}

export interface CallSite {
  callee: string;
  args: string[];
  target?: string;
  file: string;
  line: number;
}

export interface ImportInfo {
  fromFile: string;
  module: string;
  names: string[];
  line: number;
}

export interface FileExtraction {
  file: string;
  sources: Source[];
  sinks: Sink[];
  assignments: Assignment[];
  functions: FunctionDef[];
  calls: CallSite[];
  imports: ImportInfo[];
}

export interface TaintFlow {
  source: Source;
  sink: Sink;
  chain: string[];
}
