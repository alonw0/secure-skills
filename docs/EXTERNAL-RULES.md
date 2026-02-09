# External Scan Rules

The `--rules` flag lets you extend the built-in security scanner with your own custom rules. This is useful for enforcing organization-specific policies, blocking internal URLs from leaking into skills, or detecting patterns unique to your environment.

## Quick Start

```bash
# Scan with additional rules from a file
npx skills add owner/repo --rules ./my-rules.json

# Scan with all rule files in a directory
npx skills add owner/repo --rules ./rules/
```

## Rules File Format

External rules are defined in JSON files. Each file must contain a top-level object with a `rules` array:

```json
{
  "rules": [
    {
      "id": "unique-rule-id",
      "severity": "high",
      "description": "Human-readable description of what this rule detects",
      "pattern": "regex\\s+pattern\\s+here",
      "flags": "i"
    }
  ]
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier for the rule (e.g., `company-internal-api`) |
| `severity` | string | Yes | One of: `critical`, `high`, `medium`, `low`, `info` |
| `description` | string | Yes | Human-readable message shown when the rule matches |
| `pattern` | string | Yes | Regular expression pattern (as a string, without delimiters) |
| `flags` | string | No | Regex flags (default: `"i"` for case-insensitive) |

### Severity Levels

| Level | Behavior |
|-------|----------|
| `critical` | Always prompts user, even with `--yes` flag |
| `high` | Prompts user (auto-continues with `--yes`) |
| `medium` | Auto-continues with note |
| `low` | Auto-continues with note |
| `info` | Auto-continues with note |

### Pattern Syntax

Patterns use JavaScript RegExp syntax. Since patterns are JSON strings, backslashes must be double-escaped:

| Regex | JSON pattern string |
|-------|-------------------|
| `\bword\b` | `"\\bword\\b"` |
| `\s+` | `"\\s+"` |
| `https?://` | `"https?://"` |
| `\.env` | `"\\.env"` |

### Flags

The `flags` field controls regex matching behavior:

| Flag | Meaning |
|------|---------|
| `i` | Case-insensitive (default) |
| `""` | Case-sensitive (empty string) |
| `m` | Multiline (`^` and `$` match line boundaries) |
| `im` | Combine flags |

## Examples

### Block Internal URLs

```json
{
  "rules": [
    {
      "id": "internal-api-leak",
      "severity": "critical",
      "description": "References internal API — may leak infrastructure details",
      "pattern": "https?://internal\\.company\\.com"
    },
    {
      "id": "staging-url",
      "severity": "high",
      "description": "References staging environment URL",
      "pattern": "https?://staging\\."
    }
  ]
}
```

### Enforce Code Standards

```json
{
  "rules": [
    {
      "id": "no-sudo",
      "severity": "high",
      "description": "Skill should not require sudo access",
      "pattern": "\\bsudo\\s+"
    },
    {
      "id": "no-docker-run",
      "severity": "medium",
      "description": "Skill should not run arbitrary Docker containers",
      "pattern": "docker\\s+run\\s+"
    }
  ]
}
```

### Detect Deprecated Tools

```json
{
  "rules": [
    {
      "id": "deprecated-tool-xyz",
      "severity": "medium",
      "description": "References deprecated internal tool (use new-tool instead)",
      "pattern": "\\bold-tool\\b",
      "flags": "i"
    }
  ]
}
```

### Case-Sensitive Matching

```json
{
  "rules": [
    {
      "id": "exact-token-format",
      "severity": "high",
      "description": "Matches exact token prefix format",
      "pattern": "CORP_[A-Z0-9]{32}",
      "flags": ""
    }
  ]
}
```

## Using a Rules Directory

When `--rules` points to a directory, all `.json` files in that directory are loaded in alphabetical order. Non-JSON files are ignored.

```
rules/
  01-security.json      # Loaded first
  02-compliance.json    # Loaded second
  readme.txt            # Ignored
```

```bash
npx skills add owner/repo --rules ./rules/
```

This lets teams maintain separate rule files for different concerns while applying them all at once.

## How External Rules Work

External rules are applied **in addition to** the built-in scan rules. They run at the same time and their findings are combined in the scan results. They do not replace or modify built-in rules.

The scanning process:

1. Built-in rules (~50 rules) are applied first
2. External rules are applied after
3. All findings are merged and the highest severity determines the scan outcome
4. Results are presented to the user following the same severity-based flow

## Error Handling

The CLI validates external rules at load time and provides clear error messages:

- **File not found**: `External rules file not found: /path/to/rules.json`
- **Invalid JSON**: `Failed to parse /path/to/rules.json as JSON`
- **Missing rules array**: `must contain a "rules" array at the top level`
- **Invalid severity**: `has invalid severity "super-bad". Must be one of: critical, high, medium, low, info`
- **Invalid regex**: `has invalid regex pattern: Unterminated group`
- **Empty directory**: `No .json rule files found in directory: /path/to/dir/`

All validation errors halt the CLI before any scanning begins, so you'll know immediately if a rules file has issues.

## Tips

- Start with `info` severity while developing rules, then increase once you've confirmed they work
- Use [regex101.com](https://regex101.com/) (with the JavaScript flavor) to test patterns before adding them
- Keep rule IDs descriptive and namespaced (e.g., `company-no-internal-urls`)
- External rules are combined with `--vt-key` and other scan options — they're purely additive
