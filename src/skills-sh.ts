// ── Types ────────────────────────────────────────────────────────────────────

export interface SkillsShAudit {
  auditor: 'snyk' | 'socket' | 'agent-trust-hub';
  displayName: string;
  status: 'pass' | 'fail' | 'unknown';
  permalink: string;
}

export interface SkillsShResult {
  found: boolean;
  permalink: string;
  audits: SkillsShAudit[];
  anyFail: boolean;
}

export interface SkillsShSource {
  owner: string;
  repo: string;
  skillFolder: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const AUDITORS = [
  { id: 'snyk' as const, displayName: 'Snyk' },
  { id: 'socket' as const, displayName: 'Socket' },
  { id: 'agent-trust-hub' as const, displayName: 'Gen Agent Trust Hub' },
];

const NOT_FOUND: SkillsShResult = {
  found: false,
  permalink: '',
  audits: [],
  anyFail: false,
};

// ── Parsing ───────────────────────────────────────────────────────────────────

/**
 * Parse audit pass/fail status from the skills.sh page HTML.
 * For each auditor, searches within a 400-char window after the auditor's
 * security URL appears in the HTML.
 */
function parseAudits(html: string, baseUrl: string): SkillsShAudit[] {
  return AUDITORS.map(({ id, displayName }) => {
    const pattern = new RegExp(`\\/security\\/${id}[^]{0,400}?\\b(Pass|Fail)\\b`, 'is');
    const match = html.match(pattern);
    let status: 'pass' | 'fail' | 'unknown' = 'unknown';
    if (match) {
      status = match[1]!.toLowerCase() === 'pass' ? 'pass' : 'fail';
    }
    return {
      auditor: id,
      displayName,
      status,
      permalink: `${baseUrl}/security/${id}`,
    };
  });
}

// ── Main function ─────────────────────────────────────────────────────────────

/**
 * Check a skill on skills.sh and return third-party audit results.
 * Always resolves — never throws. Returns found:false on any error.
 */
export async function checkSkillOnSkillsSh(source: SkillsShSource): Promise<SkillsShResult> {
  const { owner, repo, skillFolder } = source;
  const permalink = `https://skills.sh/${owner}/${repo}/${skillFolder}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    let response: Response;
    try {
      response = await fetch(permalink, { signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      return NOT_FOUND;
    }

    const html = await response.text();
    const audits = parseAudits(html, permalink);
    const anyFail = audits.some((a) => a.status === 'fail');

    return { found: true, permalink, audits, anyFail };
  } catch {
    return NOT_FOUND;
  }
}
