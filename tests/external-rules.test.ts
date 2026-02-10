import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  parseExternalRule,
  loadExternalRulesFromFile,
  loadExternalRules,
  scanSkillContent,
} from '../src/scanner.ts';
import type { ExternalRuleDefinition } from '../src/scanner.ts';

// ── parseExternalRule ────────────────────────────────────────────────────────

describe('parseExternalRule', () => {
  it('parses a valid rule definition', () => {
    const def: ExternalRuleDefinition = {
      id: 'custom-rule',
      severity: 'high',
      description: 'Detects custom pattern',
      pattern: 'custom\\s+pattern',
    };
    const rule = parseExternalRule(def, 'test.json');
    expect(rule.id).toBe('custom-rule');
    expect(rule.severity).toBe('high');
    expect(rule.description).toBe('Detects custom pattern');
    expect(rule.pattern).toBeInstanceOf(RegExp);
    expect(rule.pattern.flags).toBe('i'); // default flags
  });

  it('uses custom regex flags', () => {
    const def: ExternalRuleDefinition = {
      id: 'case-sensitive-rule',
      severity: 'medium',
      description: 'Case sensitive match',
      pattern: 'ExactMatch',
      flags: '',
    };
    const rule = parseExternalRule(def, 'test.json');
    expect(rule.pattern.flags).toBe('');
    expect(rule.pattern.test('ExactMatch')).toBe(true);
    expect(rule.pattern.test('exactmatch')).toBe(false);
  });

  it('supports multiline flag', () => {
    const def: ExternalRuleDefinition = {
      id: 'multiline-rule',
      severity: 'low',
      description: 'Multiline match',
      pattern: '^start',
      flags: 'im',
    };
    const rule = parseExternalRule(def, 'test.json');
    expect(rule.pattern.flags).toBe('im');
  });

  it('throws on missing id', () => {
    const def = {
      severity: 'high',
      description: 'No id',
      pattern: 'test',
    } as ExternalRuleDefinition;
    expect(() => parseExternalRule(def, 'test.json')).toThrow('missing a valid "id"');
  });

  it('throws on invalid severity', () => {
    const def = {
      id: 'bad-severity',
      severity: 'super-critical' as any,
      description: 'Bad severity',
      pattern: 'test',
    };
    expect(() => parseExternalRule(def, 'test.json')).toThrow('invalid severity');
  });

  it('throws on missing description', () => {
    const def = {
      id: 'no-desc',
      severity: 'high',
      pattern: 'test',
    } as ExternalRuleDefinition;
    expect(() => parseExternalRule(def, 'test.json')).toThrow('missing a valid "description"');
  });

  it('throws on missing pattern', () => {
    const def = {
      id: 'no-pattern',
      severity: 'high',
      description: 'No pattern',
    } as ExternalRuleDefinition;
    expect(() => parseExternalRule(def, 'test.json')).toThrow('missing a valid "pattern"');
  });

  it('throws on invalid regex', () => {
    const def: ExternalRuleDefinition = {
      id: 'bad-regex',
      severity: 'high',
      description: 'Bad regex',
      pattern: '(unclosed',
    };
    expect(() => parseExternalRule(def, 'test.json')).toThrow('invalid regex pattern');
  });
});

// ── loadExternalRulesFromFile ────────────────────────────────────────────────

describe('loadExternalRulesFromFile', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = join(
      tmpdir(),
      `external-rules-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('loads a valid rules file', () => {
    const rulesFile = join(tempDir, 'rules.json');
    writeFileSync(
      rulesFile,
      JSON.stringify({
        rules: [
          {
            id: 'test-rule-1',
            severity: 'critical',
            description: 'Test rule one',
            pattern: 'dangerous_func\\(',
          },
          {
            id: 'test-rule-2',
            severity: 'low',
            description: 'Test rule two',
            pattern: 'minor_issue',
            flags: 'i',
          },
        ],
      })
    );

    const rules = loadExternalRulesFromFile(rulesFile);
    expect(rules).toHaveLength(2);
    expect(rules[0]!.id).toBe('test-rule-1');
    expect(rules[0]!.severity).toBe('critical');
    expect(rules[1]!.id).toBe('test-rule-2');
    expect(rules[1]!.pattern.flags).toBe('i');
  });

  it('throws on non-existent file', () => {
    expect(() => loadExternalRulesFromFile('/nonexistent/rules.json')).toThrow('not found');
  });

  it('throws on invalid JSON', () => {
    const rulesFile = join(tempDir, 'bad.json');
    writeFileSync(rulesFile, '{ not valid json }');
    expect(() => loadExternalRulesFromFile(rulesFile)).toThrow('Failed to parse');
  });

  it('throws when missing rules array', () => {
    const rulesFile = join(tempDir, 'no-rules.json');
    writeFileSync(rulesFile, JSON.stringify({ version: 1 }));
    expect(() => loadExternalRulesFromFile(rulesFile)).toThrow('"rules" array');
  });

  it('throws when rules is not an array', () => {
    const rulesFile = join(tempDir, 'bad-rules.json');
    writeFileSync(rulesFile, JSON.stringify({ rules: 'not-array' }));
    expect(() => loadExternalRulesFromFile(rulesFile)).toThrow('"rules" array');
  });

  it('throws on invalid rule object in array', () => {
    const rulesFile = join(tempDir, 'bad-entry.json');
    writeFileSync(rulesFile, JSON.stringify({ rules: [null] }));
    expect(() => loadExternalRulesFromFile(rulesFile)).toThrow('not a valid object');
  });

  it('loads empty rules array', () => {
    const rulesFile = join(tempDir, 'empty.json');
    writeFileSync(rulesFile, JSON.stringify({ rules: [] }));
    const rules = loadExternalRulesFromFile(rulesFile);
    expect(rules).toHaveLength(0);
  });
});

// ── loadExternalRules (file or directory) ────────────────────────────────────

describe('loadExternalRules', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = join(
      tmpdir(),
      `external-rules-dir-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('loads rules from a single file path', () => {
    const rulesFile = join(tempDir, 'rules.json');
    writeFileSync(
      rulesFile,
      JSON.stringify({
        rules: [{ id: 'file-rule', severity: 'medium', description: 'File rule', pattern: 'test' }],
      })
    );

    const rules = loadExternalRules(rulesFile);
    expect(rules).toHaveLength(1);
    expect(rules[0]!.id).toBe('file-rule');
  });

  it('loads rules from a directory of JSON files', () => {
    writeFileSync(
      join(tempDir, 'a-rules.json'),
      JSON.stringify({
        rules: [{ id: 'rule-a', severity: 'high', description: 'Rule A', pattern: 'pattern_a' }],
      })
    );
    writeFileSync(
      join(tempDir, 'b-rules.json'),
      JSON.stringify({
        rules: [
          { id: 'rule-b', severity: 'low', description: 'Rule B', pattern: 'pattern_b' },
          { id: 'rule-c', severity: 'info', description: 'Rule C', pattern: 'pattern_c' },
        ],
      })
    );
    // Non-JSON files should be ignored
    writeFileSync(join(tempDir, 'readme.txt'), 'This is not a rules file');

    const rules = loadExternalRules(tempDir);
    expect(rules).toHaveLength(3);
    // Files sorted alphabetically: a-rules.json first, then b-rules.json
    expect(rules[0]!.id).toBe('rule-a');
    expect(rules[1]!.id).toBe('rule-b');
    expect(rules[2]!.id).toBe('rule-c');
  });

  it('throws on non-existent path', () => {
    expect(() => loadExternalRules('/nonexistent/path')).toThrow('not found');
  });

  it('throws when directory has no JSON files', () => {
    writeFileSync(join(tempDir, 'readme.txt'), 'nothing here');
    expect(() => loadExternalRules(tempDir)).toThrow('No .json rule files');
  });
});

// ── scanSkillContent with external rules ─────────────────────────────────────

describe('scanSkillContent with external rules', () => {
  it('applies external rules in addition to built-in rules', () => {
    const extraRules = [
      {
        id: 'custom-forbidden-func',
        severity: 'high' as const,
        description: 'Use of forbidden function',
        pattern: /forbidden_function\(/i,
      },
    ];

    const files = new Map([['SKILL.md', 'Call forbidden_function() to do something']]);
    const result = scanSkillContent('test-skill', files, { extraRules });

    expect(result.clean).toBe(false);
    expect(result.findings.some((f) => f.rule === 'custom-forbidden-func')).toBe(true);
    expect(result.findings.find((f) => f.rule === 'custom-forbidden-func')!.severity).toBe('high');
  });

  it('returns clean when neither built-in nor external rules match', () => {
    const extraRules = [
      {
        id: 'custom-check',
        severity: 'critical' as const,
        description: 'Custom check',
        pattern: /this_will_not_match_anything_xyz123/,
      },
    ];

    const files = new Map([['SKILL.md', '# Safe Skill\n\nJust some normal instructions.']]);
    const result = scanSkillContent('safe-skill', files, { extraRules });

    expect(result.clean).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('external rules affect maxSeverity', () => {
    const extraRules = [
      {
        id: 'critical-custom',
        severity: 'critical' as const,
        description: 'Critical custom finding',
        pattern: /deploy_to_production/i,
      },
    ];

    const files = new Map([['SKILL.md', 'Run deploy_to_production immediately']]);
    const result = scanSkillContent('deploy-skill', files, { extraRules });

    expect(result.maxSeverity).toBe('critical');
  });

  it('works with no extra rules (undefined)', () => {
    const files = new Map([['SKILL.md', '# Normal skill']]);
    const result = scanSkillContent('normal-skill', files);
    expect(result.clean).toBe(true);
  });

  it('works with empty extra rules array', () => {
    const files = new Map([['SKILL.md', '# Normal skill']]);
    const result = scanSkillContent('normal-skill', files, { extraRules: [] });
    expect(result.clean).toBe(true);
  });

  it('reports correct file and line for external rule matches', () => {
    const extraRules = [
      {
        id: 'custom-detect',
        severity: 'medium' as const,
        description: 'Custom detection',
        pattern: /special_keyword/i,
      },
    ];

    const files = new Map([
      [
        'SKILL.md',
        `# My Skill

Line two content
Line three has special_keyword here
Line four is normal`,
      ],
    ]);
    const result = scanSkillContent('test', files, { extraRules });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.file).toBe('SKILL.md');
    expect(result.findings[0]!.line).toBe(4);
    expect(result.findings[0]!.matchedText).toBe('special_keyword');
  });
});

// ── End-to-end: load from file and scan ──────────────────────────────────────

describe('end-to-end external rules', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = join(tmpdir(), `e2e-rules-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('loads rules from file and uses them in scan', () => {
    const rulesFile = join(tempDir, 'company-rules.json');
    writeFileSync(
      rulesFile,
      JSON.stringify({
        rules: [
          {
            id: 'company-internal-api',
            severity: 'high',
            description: 'References internal API endpoint',
            pattern: 'internal\\.company\\.com\\/api',
          },
          {
            id: 'company-deprecated-lib',
            severity: 'medium',
            description: 'Uses deprecated library',
            pattern: 'require\\([\'"]old-library[\'"]\\)',
          },
        ],
      })
    );

    const rules = loadExternalRulesFromFile(rulesFile);

    const files = new Map([
      [
        'SKILL.md',
        `# Deploy Skill

Make API calls to internal.company.com/api/deploy
Then require('old-library') for backwards compat`,
      ],
    ]);

    const result = scanSkillContent('deploy', files, { extraRules: rules });

    expect(result.findings.filter((f) => f.rule === 'company-internal-api')).toHaveLength(1);
    expect(result.findings.filter((f) => f.rule === 'company-deprecated-lib')).toHaveLength(1);
  });
});
