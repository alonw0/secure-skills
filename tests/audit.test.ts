import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchAuditData } from '../src/telemetry.ts';

describe('fetchAuditData', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns null when skillSlugs is empty', async () => {
    const result = await fetchAuditData('owner/repo', []);
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('returns null on network error', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('Network error'));
    const result = await fetchAuditData('owner/repo', ['skill-a']);
    expect(result).toBeNull();
  });

  it('returns null on non-ok response', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: false, status: 404 } as Response);
    const result = await fetchAuditData('owner/repo', ['skill-a']);
    expect(result).toBeNull();
  });

  it('returns parsed JSON on success', async () => {
    const mockData = {
      'skill-a': {
        ath: { risk: 'safe', analyzedAt: '2025-01-01' },
        socket: { risk: 'low', alerts: 0, analyzedAt: '2025-01-01' },
        snyk: { risk: 'medium', analyzedAt: '2025-01-01' },
      },
    };
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockData),
    } as Response);

    const result = await fetchAuditData('owner/repo', ['skill-a']);

    expect(result).toEqual(mockData);
  });

  it('calls the audit API with correct query params', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    } as Response);

    await fetchAuditData('vercel-labs/agent-skills', ['skill-a', 'skill-b']);

    expect(fetch).toHaveBeenCalledOnce();
    const calledUrl = vi.mocked(fetch).mock.calls[0]![0] as string;
    expect(calledUrl).toContain('source=vercel-labs%2Fagent-skills');
    expect(calledUrl).toContain('skills=skill-a%2Cskill-b');
  });

  it('returns null on timeout', async () => {
    vi.mocked(fetch).mockImplementation(
      () =>
        new Promise((_, reject) => setTimeout(() => reject(new DOMException('', 'AbortError')), 10))
    );
    const result = await fetchAuditData('owner/repo', ['skill-a'], 5);
    expect(result).toBeNull();
  });

  it('returns null when JSON parse fails', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () => Promise.reject(new Error('Invalid JSON')),
    } as Response);
    const result = await fetchAuditData('owner/repo', ['skill-a']);
    expect(result).toBeNull();
  });
});
