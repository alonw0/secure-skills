# Deep Taint Analysis (`--deep-scan`)

The deep scan module adds forward taint propagation to the security scanner. While regex rules detect individual
dangerous patterns and the correlation engine links co-occurring signals, neither can follow data through variable
assignments or function calls. The deep scan bridges this gap.

## Why Not an AST?

TypeScript's compiler API is 9.1 MB. The entire CLI bundle is ~163 KB. Using a proper parser would 56x the bundle
size — unacceptable for an `npx`-distributed tool. Instead, both Python and JS/TS use regex-based structural
tokenizers: the same approach, with language-specific patterns. This keeps the deep scan at zero additional
dependencies.

## Architecture

```
files (Map<string, string>)
  │
  ├──▶ python-analyzer.ts ──▶ FileExtraction (per .py file)
  ├──▶ js-analyzer.ts ──────▶ FileExtraction (per .js/.ts file)
  │
  ├──▶ taint-tracker.ts ────▶ TaintFlow[] (intra-file)
  ├──▶ cross-file.ts ───────▶ TaintFlow[] (cross-file)
  │
  └──▶ index.ts ────────────▶ ScanFinding[] (merged into scanner output)
```

### Module Breakdown

| Module | Purpose |
| --- | --- |
| `types.ts` | Shared types: `Source`, `Sink`, `Assignment`, `FunctionDef`, `CallSite`, `ImportInfo`, `FileExtraction`, `TaintFlow` |
| `python-analyzer.ts` | Extracts sources, sinks, assignments, functions, calls, and imports from Python files |
| `js-analyzer.ts` | Same extraction for JavaScript and TypeScript files |
| `taint-tracker.ts` | Single-pass forward taint propagation with function-call support |
| `cross-file.ts` | Detects multi-file attack patterns via import graph analysis |
| `index.ts` | Orchestrates the pipeline; converts `TaintFlow` into `ScanFinding` |

## Sources and Sinks

### Sources (where tainted data originates)

| Kind | Python Examples | JS/TS Examples |
| --- | --- | --- |
| `env-access` | `os.environ.copy()`, `os.environ.get()`, `os.environ[key]`, `os.getenv()` | `process.env.KEY`, `process.env[key]`, `Object.keys(process.env)`, `JSON.stringify(process.env)` |
| `credential-file` | `open("/home/.aws/credentials")`, `open("~/.ssh/id_rsa")` | `fs.readFileSync("/home/.aws/credentials")` |
| `file-read` | `open(path).read()`, `Path(path).read_text()` | `fs.readFileSync(path)` |
| `getattr-trick` | `getattr(os, 'environ')`, `getattr(os, 'system')` | _(not applicable)_ |

### Sinks (where data becomes dangerous)

| Kind | Python Examples | JS/TS Examples |
| --- | --- | --- |
| `network` | `requests.post()`, `urllib.request.urlopen()`, `http.client`, `socket.send()` | `fetch()`, `axios.post()`, `https.request()` |
| `exec` | `subprocess.run()`, `os.system()`, `exec()`, `eval()` | `child_process.exec()`, `eval()`, `Function()` |
| `file-write` | `open(path, "w").write()` | `fs.writeFileSync()`, `fs.appendFileSync()` |

## Taint Propagation

The taint tracker uses a **single forward pass** (not fixpoint iteration):

1. **Seed**: Mark each source variable as tainted.
2. **Propagate**: Walk assignments in line order. If the RHS references a tainted variable, mark the LHS as tainted.
   Maintain parent pointers for chain reconstruction.
3. **Function calls**: Match call sites to function definitions. Propagate taint from arguments to parameters, and from
   tainted return variables to call targets.
4. **Detect**: Check each sink's consumed variables against the taint map. Emit a `TaintFlow` with the reconstructed
   chain.

**Complexity**: O(sources + assignments + calls + sinks) per file.

### What it catches

- Variable-mediated flows: `secret = os.environ["KEY"]; data = encode(secret); requests.post(url, data=data)`
- Multi-hop chains: 3+ variable assignments between source and sink
- Function-mediated flows: `def collect(): return os.environ.copy()` + `data = collect(); requests.post(url, data=data)`
- Evasion via getattr: `env = getattr(os, 'environ')` bypasses `os.environ` regex but not taint tracking

### What it intentionally does not catch

These are out of scope to keep complexity manageable:

- Taint through dict/list property access (`d['key'] = tainted; use(d)`)
- Control-flow-dependent taint (`if cond: x = tainted`)
- Class instance attribute flows (`self.data = tainted`)
- Inter-procedural alias analysis
- Dynamic code generation (`exec(f"...")`)

## Cross-File Analysis

The cross-file analyzer detects multi-file attack patterns where one file collects sensitive data and another
exfiltrates it. It works by:

1. **Building an import graph**: Resolve relative imports (Python `.module` syntax and JS `./module` paths) to actual
   files in the scan set.
2. **Pattern matching**: For each pair of import-connected files, check if one has sources and the other has sinks.

### Detected Patterns

| Pattern | Description | Severity |
| --- | --- | --- |
| Env exfiltration | File A has env/credential sources, file B has network sinks | critical |
| Credential separation | File A reads credential files, file B makes network calls | critical |
| Env-to-exec | File A accesses env vars, file B has exec sinks | critical |

All cross-file flows are classified as **critical** because the deliberate separation of collection and exfiltration
across files is a strong signal of malicious intent.

## Finding Format

Deep scan findings use the same `ScanFinding` interface as regex rules:

```
rule:        "deep-{source.kind}-to-{sink.kind}"         (intra-file)
             "deep-cross-{source.kind}-to-{sink.kind}"    (cross-file)
severity:    derived from source/sink combination
message:     human-readable description with file:line references
matchedText: the sink line (truncated to 120 chars)
```

### Severity Matrix

| Source | Sink | Severity |
| --- | --- | --- |
| `env-access` / `credential-file` | `network` / `exec` | critical |
| `file-read` | `network` | high |
| `getattr-trick` | any | high |
| `function-param` | `exec` / `network` | medium |
| Any cross-file flow | any | critical |

## Integration

The deep scan is wired into `scanSkillContent()` via an optional `{ deepScan: boolean }` parameter. When enabled,
`deepScanFiles()` runs after the correlation engine and merges its findings into the result. The function remains
synchronous — no changes needed at call sites beyond passing the option.

The `--deep-scan` CLI flag sets `AddOptions.deepScan`, which flows through all 4 install paths in `add.ts`.

## Testing

The test suite (`tests/deep-scan.test.ts`) covers:

- **Python analyzer**: source extraction (env, credentials, getattr, file-read), sink extraction (network, exec,
  file-write), assignments, functions, imports, continuation lines, comment stripping
- **JS/TS analyzer**: process.env sources, fetch/axios sinks, ES/CJS imports, assignments, comment stripping
- **Taint tracker**: direct flows, variable-mediated flows, multi-hop chains, no-flow cases, function-call propagation,
  getattr tricks
- **Cross-file**: import-connected env+network detection, no-flow when disconnected, credential separation
- **Integration**: `deepScanFiles()` end-to-end, `scanSkillContent()` with/without `deepScan`, coexistence with regex
  findings, clean file handling
- **Flag parsing**: `parseAddOptions` correctly sets `deepScan`
