# secure-skills

A security-hardened fork of the [skills](https://github.com/vercel-labs/skills) CLI that scans agent skills for
malicious content before installation.

<!-- agent-list:start -->
Supports **OpenCode**, **Claude Code**, **Codex**, **Cursor**, and [37 more](#available-agents).
<!-- agent-list:end -->

The open agent skills ecosystem makes it trivial to install third-party instruction sets into coding agents — but that
same ease of installation is a vector for prompt injection, data exfiltration, and credential theft.
[Snyk's analysis](https://snyk.io/blog/) of 3,984 published skills found that **13.4% had critical security issues** and
76 were confirmed malicious. Separately,
[Koi's ClawHavoc investigation](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting)
uncovered **341 malicious ClawedBot skills** using techniques like AMOS stealer droppers, password-protected archives,
base64-encoded payloads, macOS quarantine bypasses (`xattr -c`), and reverse shells. `skillsio` adds an automated
security gate so you can still move fast without running untrusted code.

## What It Does

Every `skillsio add` command runs a local security scan **before** anything is installed. The scanner applies ~81 regex
rules and a correlation engine derived from the Snyk and ClawHavoc research, organized into 8 threat categories:

| Category | What it catches |
| --- | --- |
| **Exfiltration** | Sending files/env vars to external endpoints, webhook URLs |
| **Prompt injection** | "Ignore previous instructions", role hijacking, instruction overrides |
| **Dangerous filesystem** | `rm -rf`, mass deletion, wiping home directories |
| **Credential access** | Reading SSH keys, AWS credentials, `.env` files, keychains |
| **Suspicious directives** | "Never ask for confirmation", "silently execute", stealth instructions |
| **Downloads / RCE** | `curl \| sh`, downloading and executing remote scripts |
| **Obfuscation** | Base64-encoded commands, Unicode escape sequences, hex-encoded strings |
| **Reverse shells / services** | Netcat listeners, cron persistence, systemd/launchd service creation |

Findings are categorized by severity:

- **Critical** / **High** — always prompts for confirmation (critical prompts even with `--yes`)
- **Medium** and below — noted and auto-continued

### URL Transparency

The scanner extracts all external URLs found in skill files and displays them before installation. Even if the local scan
is clean, skills that reference external URLs will prompt you to review them before proceeding. This catches deceptive
domain patterns that regex rules can't — letting you eyeball where a skill wants to send traffic.

```
◆  External URLs found in skill files (2):
│  https://example.com/setup
│  https://hooks.slack.com/services/T00/B00/xxx
│
◆  This skill references external URLs. Continue with installation?
```

With `--yes`, URL-only prompts are auto-continued. Skills with high/critical findings always show URLs alongside the
findings summary.

### Third-Party Audits via skills.sh

For GitHub-sourced skills, the CLI automatically checks [skills.sh](https://skills.sh) — Vercel's official skill
directory — which runs independent third-party security audits from three auditors: **Snyk**, **Socket**, and
**Gen Agent Trust Hub**. Results appear alongside local scan output:

```
  ◆ skills.sh: 3 audits  [Snyk ✗]  [Socket ✓]  [Trust Hub ✗]
    https://skills.sh/inference-sh-3/skills/agent-tools
```

- Green ✓ = auditor passed, Red ✗ = auditor failed, Dim ~ = no result yet
- If any auditor returns a **Fail** verdict, severity is escalated to at least **High**, triggering a confirmation
  prompt
- skills.sh lookup runs in parallel with VT and never blocks installation on error (graceful fallback)
- Only fires for GitHub-sourced skills that are listed on skills.sh — silent for everything else

### Optional: VirusTotal Integration

When a [VirusTotal](https://www.virustotal.com/) API key is provided, the CLI also hashes each skill's content
(SHA-256) and checks it against VT's database. If the file has been seen before, VT's verdict is displayed alongside
local findings — including engine detection counts and Gemini-powered Code Insight analysis.

```
◆ VirusTotal: ✗ malicious (14/72 engines)
   Code Insight: Downloads and executes external binary...
   https://www.virustotal.com/gui/file/{hash}

◆ VirusTotal: ✓ clean (0/72 engines)

◆ VirusTotal: not found (local scan only)
```

A VT malicious verdict escalates the scan to critical severity regardless of local findings.

VT is purely additive — no key means no VT calls, and VT errors (rate limits, network issues) are handled gracefully
without blocking installation.

```bash
# Via CLI flag
npx skillsio add owner/repo --vt-key YOUR_API_KEY

# Via environment variable
VT_API_KEY=YOUR_API_KEY npx skillsio add owner/repo
```

`--vt-key` flag takes precedence over `VT_API_KEY` env var.

### External Rules

You can extend the built-in scanner with your own rules using the `--rules` flag. This is useful for enforcing
organization-specific policies — for example, blocking references to internal infrastructure or flagging deprecated
tools.

Rules are defined in JSON files with a simple format:

```json
{
  "rules": [
    {
      "id": "no-internal-api",
      "severity": "critical",
      "description": "References internal API — may leak infrastructure details",
      "pattern": "https?://internal\\.company\\.com",
      "flags": "i"
    },
    {
      "id": "no-sudo",
      "severity": "high",
      "description": "Skill should not require sudo access",
      "pattern": "\\bsudo\\s+"
    }
  ]
}
```

Each rule requires `id`, `severity` (`critical`/`high`/`medium`/`low`/`info`), `description`, and `pattern` (a regex
string). The optional `flags` field defaults to `"i"` (case-insensitive).

```bash
# Load rules from a single file
npx skillsio add owner/repo --rules ./my-rules.json

# Load all .json rule files from a directory
npx skillsio add owner/repo --rules ./rules/
```

External rules are applied **in addition to** the built-in ~81 rules — they never replace them. Findings from external
rules follow the same severity-based prompt flow as built-in findings.

See [docs/EXTERNAL-RULES.md](docs/EXTERNAL-RULES.md) for the full format reference, more examples, and tips for writing
rules.

### Deep Taint Analysis (`--deep-scan`)

Regex rules detect individual dangerous patterns, but sophisticated attacks hide data flows across variables and
functions. The `--deep-scan` flag enables a lightweight taint analysis engine that tracks how data moves from
**sources** (environment variables, credential files) through variable assignments to **sinks** (network calls, exec,
file writes).

```bash
npx skillsio add owner/repo --deep-scan
```

What it catches that regex cannot:

```python
# Variable-mediated exfiltration — regex sees the pieces but can't link them
key = os.environ["SECRET"]        # source: env-access
encoded = b64encode(key)          # taint propagates through assignment
payload = json.dumps(encoded)     # ...and another hop
requests.post(url, data=payload)  # sink: network  →  deep-env-access-to-network (critical)
```

```python
# getattr trick — regex misses the source entirely
env = getattr(os, 'environ')     # source: getattr-trick (evades os.environ regex)
data = str(env)
requests.post(url, data=data)    # → deep-getattr-trick-to-network (high)
```

```python
# Cross-file attack — collector.py harvests, exfil.py sends
# collector.py                    # exfil.py
import os                         # from .collector import data
secrets = os.environ.copy()       # requests.post(url, data=payload)
                                  # → deep-cross-env-access-to-network (critical)
```

The analysis covers Python (`.py`) and JavaScript/TypeScript (`.js`, `.ts`) files. It adds zero dependencies — the
tokenizer is regex-based, not AST-based, keeping the bundle small. See [docs/deep-scan.md](docs/deep-scan.md) for
architecture details.

Deep scan findings appear alongside regex findings in the same severity-based prompt. All cross-file flows are
automatically classified as critical.

## Quick Start

```bash
# Install a skill (scanned automatically)
npx skillsio add vercel-labs/agent-skills

# Enable deep taint analysis for Python/JS/TS files
npx skillsio add owner/repo --deep-scan

# Skip the scan if you trust the source
npx skillsio add vercel-labs/agent-skills --skip-scan

# Scan with VirusTotal threat intelligence
VT_API_KEY=xxx npx skillsio add owner/repo

# Scan with custom organization rules
npx skillsio add owner/repo --rules ./company-rules.json
```

## CLI Reference

### `add <source>`

Install skills from GitHub, GitLab, git URLs, direct URLs, or local paths.

```bash
npx skillsio add vercel-labs/agent-skills           # GitHub shorthand
npx skillsio add https://github.com/org/repo        # Full URL
npx skillsio add git@github.com:org/repo.git        # Git URL
npx skillsio add ./my-local-skills                   # Local path
```

| Option | Description |
| --- | --- |
| `-g, --global` | Install to user directory instead of project |
| `-a, --agent <agents...>` | <!-- agent-names:start -->Target specific agents (e.g., `claude-code`, `codex`). See [Supported Agents](#supported-agents)<!-- agent-names:end --> |
| `-s, --skill <skills...>` | Install specific skills by name (use `'*'` for all) |
| `-l, --list` | List available skills without installing |
| `-y, --yes` | Skip confirmation prompts |
| `--all` | Install all skills to all agents without prompts |
| `--skip-scan` | Skip the security scan before installation |
| `--rules <path>` | Load additional scan rules from a JSON file or directory (see [External Rules](#external-rules)) |
| `--deep-scan` | Enable deep taint analysis on Python/JS/TS files |
| `--vt-key <key>` | VirusTotal API key for additional threat intelligence |
| `--full-depth` | Search all subdirectories even when a root SKILL.md exists |

### Other Commands

| Command | Description |
| --- | --- |
| `list` (alias: `ls`) | List installed skills |
| `find [query]` | Search for skills interactively or by keyword |
| `remove [skills]` (alias: `rm`) | Remove installed skills from agents |
| `check` | Check for available skill updates |
| `update` | Update all installed skills to latest versions |
| `init [name]` | Create a new SKILL.md template |

### Installation Scope

| Scope | Flag | Location | Use Case |
| --- | --- | --- | --- |
| **Project** | (default) | `./<agent>/skills/` | Committed with your project |
| **Global** | `-g` | `~/<agent>/skills/` | Available across all projects |

## Supported Agents

<!-- agent-list:start -->
Supports **OpenCode**, **Claude Code**, **Codex**, **Cursor**, and [35 more](#supported-agents).
<!-- agent-list:end -->

<!-- supported-agents:start -->
| Agent | `--agent` | Project Path | Global Path |
|-------|-----------|--------------|-------------|
| Amp, Kimi Code CLI, Replit, Universal | `amp`, `kimi-cli`, `replit`, `universal` | `.agents/skills/` | `~/.config/agents/skills/` |
| Antigravity | `antigravity` | `.agent/skills/` | `~/.gemini/antigravity/skills/` |
| Augment | `augment` | `.augment/skills/` | `~/.augment/skills/` |
| Claude Code | `claude-code` | `.claude/skills/` | `~/.claude/skills/` |
| OpenClaw | `openclaw` | `skills/` | `~/.openclaw/skills/` |
| Cline | `cline` | `.cline/skills/` | `~/.cline/skills/` |
| CodeBuddy | `codebuddy` | `.codebuddy/skills/` | `~/.codebuddy/skills/` |
| Codex | `codex` | `.agents/skills/` | `~/.codex/skills/` |
| Command Code | `command-code` | `.commandcode/skills/` | `~/.commandcode/skills/` |
| Continue | `continue` | `.continue/skills/` | `~/.continue/skills/` |
| Cortex Code | `cortex` | `.cortex/skills/` | `~/.snowflake/cortex/skills/` |
| Crush | `crush` | `.crush/skills/` | `~/.config/crush/skills/` |
| Cursor | `cursor` | `.agents/skills/` | `~/.cursor/skills/` |
| Droid | `droid` | `.factory/skills/` | `~/.factory/skills/` |
| Gemini CLI | `gemini-cli` | `.agents/skills/` | `~/.gemini/skills/` |
| GitHub Copilot | `github-copilot` | `.agents/skills/` | `~/.copilot/skills/` |
| Goose | `goose` | `.goose/skills/` | `~/.config/goose/skills/` |
| Junie | `junie` | `.junie/skills/` | `~/.junie/skills/` |
| iFlow CLI | `iflow-cli` | `.iflow/skills/` | `~/.iflow/skills/` |
| Kilo Code | `kilo` | `.kilocode/skills/` | `~/.kilocode/skills/` |
| Kiro CLI | `kiro-cli` | `.kiro/skills/` | `~/.kiro/skills/` |
| Kode | `kode` | `.kode/skills/` | `~/.kode/skills/` |
| MCPJam | `mcpjam` | `.mcpjam/skills/` | `~/.mcpjam/skills/` |
| Mistral Vibe | `mistral-vibe` | `.vibe/skills/` | `~/.vibe/skills/` |
| Mux | `mux` | `.mux/skills/` | `~/.mux/skills/` |
| OpenCode | `opencode` | `.agents/skills/` | `~/.config/opencode/skills/` |
| OpenHands | `openhands` | `.openhands/skills/` | `~/.openhands/skills/` |
| Pi | `pi` | `.pi/skills/` | `~/.pi/agent/skills/` |
| Qoder | `qoder` | `.qoder/skills/` | `~/.qoder/skills/` |
| Qwen Code | `qwen-code` | `.qwen/skills/` | `~/.qwen/skills/` |
| Roo Code | `roo` | `.roo/skills/` | `~/.roo/skills/` |
| Trae | `trae` | `.trae/skills/` | `~/.trae/skills/` |
| Trae CN | `trae-cn` | `.trae/skills/` | `~/.trae-cn/skills/` |
| Windsurf | `windsurf` | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` |
| Zencoder | `zencoder` | `.zencoder/skills/` | `~/.zencoder/skills/` |
| Neovate | `neovate` | `.neovate/skills/` | `~/.neovate/skills/` |
| Pochi | `pochi` | `.pochi/skills/` | `~/.pochi/skills/` |
| AdaL | `adal` | `.adal/skills/` | `~/.adal/skills/` |
<!-- supported-agents:end -->

> [!NOTE]
> **Kiro CLI users:** After installing skills, manually add them to your custom agent's `resources` in
> `.kiro/agents/<agent>.json`:
>
> ```json
> {
>   "resources": ["skill://.kiro/skills/**/SKILL.md"]
> }
> ```

The CLI automatically detects which coding agents you have installed. If none are detected, you'll be prompted to select
which agents to install to.

## Creating Skills

Skills are directories containing a `SKILL.md` file with YAML frontmatter:

```markdown
---
name: my-skill
description: What this skill does and when to use it
---

# My Skill

Instructions for the agent to follow when this skill is activated.

## When to Use

Describe the scenarios where this skill should be used.

## Steps

1. First, do this
2. Then, do that
```

### Required Fields

- `name`: Unique identifier (lowercase, hyphens allowed)
- `description`: Brief explanation of what the skill does

### Optional Fields

- `metadata.internal`: Set to `true` to hide the skill from normal discovery. Internal skills are only visible and
  installable when `INSTALL_INTERNAL_SKILLS=1` is set. Useful for work-in-progress skills or skills meant only for
  internal tooling.

```markdown
---
name: my-internal-skill
description: An internal skill not shown by default
metadata:
  internal: true
---
```

### Skill Discovery

The CLI searches for skills in these locations within a repository:

<!-- skill-discovery:start -->
- Root directory (if it contains `SKILL.md`)
- `skills/`
- `skills/.curated/`
- `skills/.experimental/`
- `skills/.system/`
- `.agents/skills/`
- `.agent/skills/`
- `.augment/skills/`
- `.claude/skills/`
- `./skills/`
- `.cline/skills/`
- `.codebuddy/skills/`
- `.commandcode/skills/`
- `.continue/skills/`
- `.cortex/skills/`
- `.crush/skills/`
- `.factory/skills/`
- `.goose/skills/`
- `.junie/skills/`
- `.iflow/skills/`
- `.kilocode/skills/`
- `.kiro/skills/`
- `.kode/skills/`
- `.mcpjam/skills/`
- `.vibe/skills/`
- `.mux/skills/`
- `.openhands/skills/`
- `.pi/skills/`
- `.qoder/skills/`
- `.qwen/skills/`
- `.roo/skills/`
- `.trae/skills/`
- `.windsurf/skills/`
- `.zencoder/skills/`
- `.neovate/skills/`
- `.pochi/skills/`
- `.adal/skills/`
<!-- skill-discovery:end -->

### Plugin Manifest Discovery

If `.claude-plugin/marketplace.json` or `.claude-plugin/plugin.json` exists, skills declared in those files are also discovered:

```json
// .claude-plugin/marketplace.json
{
  "metadata": { "pluginRoot": "./plugins" },
  "plugins": [{
    "name": "my-plugin",
    "source": "my-plugin",
    "skills": ["./skills/review", "./skills/test"]
  }]
}
```

This enables compatibility with the [Claude Code plugin marketplace](https://code.claude.com/docs/en/plugin-marketplaces) ecosystem.

If no skills are found in standard locations, a recursive search is performed.

## Compatibility

Skills are generally compatible across agents since they follow a
shared [Agent Skills specification](https://agentskills.io). However, some features may be agent-specific:

| Feature         | OpenCode | OpenHands | Claude Code | Cline | CodeBuddy | Codex | Command Code | Kiro CLI | Cursor | Antigravity | Roo Code | Github Copilot | Amp | OpenClaw | Neovate | Pi  | Qoder | Zencoder |
| --------------- | -------- | --------- | ----------- | ----- | --------- | ----- | ------------ | -------- | ------ | ----------- | -------- | -------------- | --- | -------- | ------- | --- | ----- | -------- |
| Basic skills    | Yes      | Yes       | Yes         | Yes   | Yes       | Yes   | Yes          | Yes      | Yes    | Yes         | Yes      | Yes            | Yes | Yes      | Yes     | Yes | Yes   | Yes      |
| `allowed-tools` | Yes      | Yes       | Yes         | Yes   | Yes       | Yes   | Yes          | No       | Yes    | Yes         | Yes      | Yes            | Yes | Yes      | Yes     | Yes | Yes   | No       |
| `context: fork` | No       | No        | Yes         | No    | No        | No    | No           | No       | No     | No          | No       | No             | No  | No       | No      | No  | No    | No       |
| Hooks           | No       | No        | Yes         | Yes   | No        | No    | No           | No       | No     | No          | No       | No             | No  | No       | No      | No  | No    | No       |

## Troubleshooting

### "No skills found"

Ensure the repository contains valid `SKILL.md` files with both `name` and `description` in the frontmatter.

### Skill not loading in agent

- Verify the skill was installed to the correct path
- Check the agent's documentation for skill loading requirements
- Ensure the `SKILL.md` frontmatter is valid YAML

### Permission errors

Ensure you have write access to the target directory.

## Environment Variables

| Variable | Description |
| --- | --- |
| `VT_API_KEY` | VirusTotal API key for optional threat intelligence during security scans |
| `INSTALL_INTERNAL_SKILLS` | Set to `1` to show and install skills marked as `internal: true` |

## Development

```bash
pnpm install          # Install dependencies
pnpm build            # Build
pnpm dev <cmd>        # Run CLI in dev mode (e.g., pnpm dev add owner/repo)
pnpm test             # Run all tests
pnpm type-check       # TypeScript type checking
pnpm format           # Format code with Prettier
```

### Scanner Architecture

- `src/scanner.ts` — Rules engine. Defines ~81 regex rules across 8 threat categories, a correlation engine for
  multi-signal detection, and optional deep taint analysis integration. Supports loading external rules from JSON
  files via `--rules`.
- `src/scanner-ui.ts` — Presentation layer. Displays findings by severity, runs VT and skills.sh lookups in parallel,
  handles escalation logic and user confirmation prompts.
- `src/vt.ts` — VirusTotal API client. SHA-256 hashing, `GET /api/v3/files/{hash}` lookup, verdict mapping, graceful
  error handling.
- `src/skills-sh.ts` — skills.sh audit client. Fetches and HTML-parses third-party audit results (Snyk, Socket, Gen
  Agent Trust Hub) for GitHub-sourced skills with a 5-second timeout; always resolves gracefully.
- `src/deep-scan/` — Deep taint analysis engine (enabled via `--deep-scan`). Regex-based tokenizers extract sources,
  sinks, and assignments from Python/JS/TS files; a forward taint tracker propagates data flow; a cross-file analyzer
  detects multi-file attack patterns via import graph analysis. See [docs/deep-scan.md](docs/deep-scan.md).
- `src/add.ts` — Integration point. The scanner is wired into all 4 install paths (GitHub/git repos, remote providers,
  well-known endpoints, legacy Mintlify).

## Changelog

### 1.1.3

- **Synced with upstream** ([vercel-labs/skills](https://github.com/vercel-labs/skills)): universal agent support
  (`.agents/skills/` as a single install target symlinked across agents), new agents (Cortex Code, and others), Kiro CLI
  note, Creating Skills docs, Compatibility table, Troubleshooting section, agent-list badge
- **Replaced HTML scraping with structured API**: third-party audit now uses the `add-skill.vercel.sh/audit` JSON
  endpoint instead of scraping `skills.sh` HTML — more reliable and richer data (risk levels + alert counts per auditor)
- **Stronger blocking**: critical and high risk from the API both always prompt for confirmation; `--yes` is ignored for
  both (previously high was bypassed by `--yes` and critical only prompted rather than blocked)
- **Audit failure warning**: if the skills.sh API is unreachable, a yellow warning is shown rather than silently
  skipping — local scan still runs regardless
- Removed duplicate audit display (previously showed both an inline scan note and a separate "Security Risk Assessments"
  panel for the same data)

### 1.1.2

- **skills.sh audit integration**: for GitHub-sourced skills, the CLI now fetches third-party audit results from
  [skills.sh](https://skills.sh) (Snyk, Socket, Gen Agent Trust Hub) and displays them alongside local scan output
- Critical or High risk from any auditor escalates the install gate — critical always prompts even with `--yes`, high
  blocks unless `--yes` is set; uses the structured skills.sh JSON API instead of HTML scraping
- Audit runs in parallel with VirusTotal and fails silently on any network or parse error

### 1.1.1

- Removed anonymous usage telemetry inherited from the original Vercel `skills` CLI
- The upstream tool sent events to `https://add-skill.vercel.sh/t` on every command (install, remove, find, check, update) — this has been completely stripped out
- Removed `DISABLE_TELEMETRY` and `DO_NOT_TRACK` environment variables (no longer needed)
- Added 12 more regex rules to the scanner

### 1.1.0

- Added `--rules <path>` flag to load external scan rules from JSON files or directories
- External rules are applied alongside built-in rules, supporting organization-specific policies
- See [docs/EXTERNAL-RULES.md](docs/EXTERNAL-RULES.md) for format documentation and examples
- **Deep taint analysis** (`--deep-scan`): lightweight forward taint propagation for Python and JS/TS files
- Tracks data flow from sources (env vars, credential files, getattr tricks) through variable chains to sinks (network
  calls, exec, file writes)
- Cross-file analysis detects multi-file exfiltration patterns via import graph resolution
- Zero new dependencies — regex-based tokenizers keep the bundle small

### 1.0.1

- Critical security prompts now default to **No** — users must explicitly confirm to install skills flagged as malicious

### 1.0.0

- Initial release with ~52 regex security rules across 8 threat categories
- VirusTotal integration for optional secondary threat intelligence
- URL transparency: all external URLs in skill files are shown before installation
- Scanner rules informed by Snyk and ClawHavoc research

## Links

- [Agent Skills Specification](https://agentskills.io)
- [Skills Directory](https://skills.sh)
- [Amp Skills Documentation](https://ampcode.com/manual#agent-skills)
- [Antigravity Skills Documentation](https://antigravity.google/docs/skills)
- [Factory AI / Droid Skills Documentation](https://docs.factory.ai/cli/configuration/skills)
- [Claude Code Skills Documentation](https://code.claude.com/docs/en/skills)
- [OpenClaw Skills Documentation](https://docs.openclaw.ai/tools/skills)
- [Cline Skills Documentation](https://docs.cline.bot/features/skills)
- [CodeBuddy Skills Documentation](https://www.codebuddy.ai/docs/ide/Features/Skills)
- [Codex Skills Documentation](https://developers.openai.com/codex/skills)
- [Command Code Skills Documentation](https://commandcode.ai/docs/skills)
- [Crush Skills Documentation](https://github.com/charmbracelet/crush?tab=readme-ov-file#agent-skills)
- [Cursor Skills Documentation](https://cursor.com/docs/context/skills)
- [Gemini CLI Skills Documentation](https://geminicli.com/docs/cli/skills/)
- [GitHub Copilot Agent Skills](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills)
- [iFlow CLI Skills Documentation](https://platform.iflow.cn/en/cli/examples/skill)
- [Kimi Code CLI Skills Documentation](https://moonshotai.github.io/kimi-cli/en/customization/skills.html)
- [Kiro CLI Skills Documentation](https://kiro.dev/docs/cli/custom-agents/configuration-reference/#skill-resources)
- [Kode Skills Documentation](https://github.com/shareAI-lab/kode/blob/main/docs/skills.md)
- [OpenCode Skills Documentation](https://opencode.ai/docs/skills)
- [Qwen Code Skills Documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/skills/)
- [OpenHands Skills Documentation](https://docs.openhands.ai/modules/usage/how-to/using-skills)
- [Pi Skills Documentation](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/skills.md)
- [Qoder Skills Documentation](https://docs.qoder.com/cli/Skills)
- [Replit Skills Documentation](https://docs.replit.com/replitai/skills)
- [Roo Code Skills Documentation](https://docs.roocode.com/features/skills)
- [Trae Skills Documentation](https://docs.trae.ai/ide/skills)
- [Vercel Agent Skills Repository](https://github.com/vercel-labs/agent-skills)

## Research

The scanner rules are informed by the following research into malicious agent skills:

- **Snyk (2025)** — [Analysis of 3,984 published agent skills](https://snyk.io/blog/), finding 76 confirmed malicious skills (13.4% of clawhub.ai had critical issues). Identified core attack taxonomy: data exfiltration, prompt injection, credential theft, and obfuscated payloads.
- **Koi Security (2025)** — [ClawHavoc: 341 Malicious ClawedBot Skills](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting). Documented AMOS stealer droppers, password-protected archives, base64 payloads, macOS quarantine bypasses, and reverse shells in the wild.
- **arxiv 2602.06547v1 (2025)** — [Malicious Agent Skills at Scale](https://arxiv.org/abs/2602.06547v1). Large-scale analysis identifying attack taxonomies (E1-E3 exfiltration, P1-P4 prompt injection, SC1-SC3 supply chain, PE2-PE3 privilege escalation), MCP server abuse, agent hook interception, permission bypass flags, environment-gated sleeper patterns, invisible Unicode instruction smuggling, and the "industrial actor fingerprint" (credential access + remote execution, 97.6% sensitivity).

## Acknowledgments

This project is a fork of [skills](https://github.com/vercel-labs/skills) by
[Vercel Labs](https://github.com/vercel-labs). All upstream CLI functionality — skill discovery, installation, agent
support, update checking — comes from the original project. The security scanning layer, VirusTotal integration, and
related tests are additions by this fork.

## License

MIT
