import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkSkillOnSkillsSh, type SkillsShSource } from '../src/skills-sh.ts';

const source: SkillsShSource = {
  owner: 'inference-sh-3',
  repo: 'skills',
  skillFolder: 'agent-tools',
};

describe('checkSkillOnSkillsSh', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns found:false on 404', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 404,
      text: () => Promise.resolve(''),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    expect(result.found).toBe(false);
    expect(result.audits).toEqual([]);
    expect(result.anyFail).toBe(false);
    expect(result.permalink).toBe('');
  });

  it('returns found:false on network error', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('Network error'));

    const result = await checkSkillOnSkillsSh(source);

    expect(result.found).toBe(false);
    expect(result.audits).toEqual([]);
    expect(result.anyFail).toBe(false);
  });

  it('parses all three auditors from HTML', async () => {
    const html = `
      <html>
        <body>
          <a href="/inference-sh-3/skills/agent-tools/security/snyk">Snyk</a>
          <span>Fail</span>
          <a href="/inference-sh-3/skills/agent-tools/security/socket">Socket</a>
          <span>Pass</span>
          <a href="/inference-sh-3/skills/agent-tools/security/agent-trust-hub">Gen Agent Trust Hub</a>
          <span>Fail</span>
        </body>
      </html>
    `;

    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(html),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    expect(result.found).toBe(true);

    const snyk = result.audits.find((a) => a.auditor === 'snyk');
    const socket = result.audits.find((a) => a.auditor === 'socket');
    const trustHub = result.audits.find((a) => a.auditor === 'agent-trust-hub');

    expect(snyk?.status).toBe('fail');
    expect(socket?.status).toBe('pass');
    expect(trustHub?.status).toBe('fail');
  });

  it('returns anyFail:true when any auditor fails', async () => {
    const html = `
      /security/snyk ... Fail
      /security/socket ... Pass
      /security/agent-trust-hub ... Pass
    `;

    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(html),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    expect(result.found).toBe(true);
    expect(result.anyFail).toBe(true);
  });

  it('returns anyFail:false when all auditors pass', async () => {
    const html = `
      /security/snyk ... Pass
      /security/socket ... Pass
      /security/agent-trust-hub ... Pass
    `;

    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(html),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    expect(result.found).toBe(true);
    expect(result.anyFail).toBe(false);
    expect(result.audits.every((a) => a.status === 'pass')).toBe(true);
  });

  it('returns unknown status when auditor URL not in HTML', async () => {
    // HTML with no audit sections at all
    const html = `<html><body><h1>Skill: agent-tools</h1></body></html>`;

    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(html),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    expect(result.found).toBe(true);
    expect(result.audits.every((a) => a.status === 'unknown')).toBe(true);
    expect(result.anyFail).toBe(false);
  });

  it('correctly constructs permalink from source', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () =>
        Promise.resolve('/security/snyk Pass /security/socket Pass /security/agent-trust-hub Pass'),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    expect(result.permalink).toBe('https://skills.sh/inference-sh-3/skills/agent-tools');
    expect(fetch).toHaveBeenCalledWith(
      'https://skills.sh/inference-sh-3/skills/agent-tools',
      expect.objectContaining({ signal: expect.any(AbortSignal) })
    );
  });

  it('sets correct display names and audit permalinks', async () => {
    const html = `/security/snyk Pass /security/socket Pass /security/agent-trust-hub Pass`;

    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(html),
    } as Response);

    const result = await checkSkillOnSkillsSh(source);

    const snyk = result.audits.find((a) => a.auditor === 'snyk');
    const socket = result.audits.find((a) => a.auditor === 'socket');
    const trustHub = result.audits.find((a) => a.auditor === 'agent-trust-hub');

    expect(snyk?.displayName).toBe('Snyk');
    expect(snyk?.permalink).toBe(
      'https://skills.sh/inference-sh-3/skills/agent-tools/security/snyk'
    );

    expect(socket?.displayName).toBe('Socket');
    expect(socket?.permalink).toBe(
      'https://skills.sh/inference-sh-3/skills/agent-tools/security/socket'
    );

    expect(trustHub?.displayName).toBe('Gen Agent Trust Hub');
    expect(trustHub?.permalink).toBe(
      'https://skills.sh/inference-sh-3/skills/agent-tools/security/agent-trust-hub'
    );
  });
});
