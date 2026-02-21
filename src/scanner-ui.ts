import * as p from '@clack/prompts';
import pc from 'picocolors';
import type { ScanResult, ScanSeverity } from './scanner.ts';
import { checkSkillOnVT, type VTVerdict } from './vt.ts';
import { fetchAuditData, type SkillAuditData, type PartnerAudit } from './telemetry.ts';

const SEVERITY_LABELS: Record<ScanSeverity, string> = {
  critical: pc.bgRed(pc.white(pc.bold(' CRITICAL '))),
  high: pc.red(pc.bold('HIGH')),
  medium: pc.yellow('MEDIUM'),
  low: pc.blue('LOW'),
  info: pc.dim('INFO'),
};

const SEVERITY_ORDER: Record<ScanSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const AUDIT_RISK_ORDER: Record<string, number> = {
  unknown: 0,
  safe: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function displayVTVerdict(verdict: VTVerdict): void {
  if (!verdict.found) {
    p.log.message(pc.dim('  VirusTotal: not found (local scan only)'));
    return;
  }

  if (verdict.verdict === 'malicious') {
    p.log.message(
      `  ${pc.red('◆ VirusTotal: ✗ malicious')} ${pc.dim(`(${verdict.maliciousCount}/${verdict.totalEngines} engines)`)}`
    );
  } else if (verdict.verdict === 'suspicious') {
    p.log.message(
      `  ${pc.yellow('◆ VirusTotal: ⚠ suspicious')} ${pc.dim(`(${verdict.maliciousCount}/${verdict.totalEngines} engines)`)}`
    );
  } else {
    p.log.message(
      `  ${pc.green('◆ VirusTotal: ✓ clean')} ${pc.dim(`(${verdict.maliciousCount}/${verdict.totalEngines} engines)`)}`
    );
  }

  if (verdict.codeInsight) {
    const truncated =
      verdict.codeInsight.length > 200
        ? verdict.codeInsight.slice(0, 197) + '...'
        : verdict.codeInsight;
    p.log.message(pc.dim(`    Code Insight: ${truncated}`));
  }

  if (verdict.permalink) {
    p.log.message(pc.dim(`    ${verdict.permalink}`));
  }
}

function auditRiskBadge(displayName: string, audit: PartnerAudit): string {
  const alerts =
    audit.alerts != null && audit.alerts > 0
      ? ` ${audit.alerts} alert${audit.alerts !== 1 ? 's' : ''}`
      : '';
  switch (audit.risk) {
    case 'critical':
      return `[${pc.red(pc.bold(`${displayName} ✗ critical${alerts}`))}]`;
    case 'high':
      return `[${pc.red(`${displayName} ✗ high${alerts}`)}]`;
    case 'medium':
      return `[${pc.yellow(`${displayName} ⚠ medium${alerts}`)}]`;
    case 'low':
      return `[${pc.green(`${displayName} ✓ low`)}]`;
    case 'safe':
      return `[${pc.green(`${displayName} ✓`)}]`;
    default:
      return `[${pc.dim(`${displayName} ~`)}]`;
  }
}

const AUDITORS = [
  { id: 'ath', displayName: 'Trust Hub' },
  { id: 'socket', displayName: 'Socket' },
  { id: 'snyk', displayName: 'Snyk' },
] as const;

function displayAuditResults(
  skillNames: string[],
  auditData: Record<string, SkillAuditData>,
  source: string
): void {
  const hasData = skillNames.some((name) => {
    const data = auditData[name];
    return data && Object.keys(data).length > 0;
  });
  if (!hasData) return;

  for (const skillName of skillNames) {
    const data = auditData[skillName];
    if (!data || Object.keys(data).length === 0) continue;

    const badges = AUDITORS.map(({ id, displayName }) => {
      const audit = data[id];
      return audit ? auditRiskBadge(displayName, audit) : `[${pc.dim(`${displayName} ~`)}]`;
    }).join('  ');

    const label = skillNames.length > 1 ? `${pc.cyan(skillName)}: ` : '';
    p.log.message(`  ${pc.cyan('◆')} ${label}${badges}`);
  }
  p.log.message(pc.dim(`    https://skills.sh/${source}`));
}

/** Maximum risk level across all auditors and all skills. Returns null if no audit data. */
function maxAuditRisk(
  skillNames: string[],
  auditData: Record<string, SkillAuditData>
): 'critical' | 'high' | null {
  let max = 0;
  for (const skillName of skillNames) {
    const data = auditData[skillName];
    if (!data) continue;
    for (const audit of Object.values(data)) {
      const level = AUDIT_RISK_ORDER[audit.risk] ?? 0;
      if (level > max) max = level;
    }
  }
  if (max >= 4) return 'critical';
  if (max >= 3) return 'high';
  return null;
}

export interface PresentScanOptions {
  yes?: boolean;
  vtKey?: string;
  /** Map of skill name → primary content (SKILL.md) for VT hash lookup */
  skillContents?: Map<string, string>;
  /** owner/repo string for skills.sh API audit lookup, e.g. "vercel-labs/agent-skills" */
  auditSource?: string;
}

/**
 * Present scan results to the user and decide whether to proceed.
 * Returns true to continue installation, false to abort.
 */
export async function presentScanResults(
  results: ScanResult[],
  options: PresentScanOptions
): Promise<boolean> {
  const allFindings = results.flatMap((r) =>
    r.findings.map((f) => ({ ...f, skillName: r.skillName }))
  );

  // Collect all URLs across results
  const allUrls = [...new Set(results.flatMap((r) => r.urls))];

  const skillNames = results.map((r) => r.skillName);

  // Run VT and skills.sh API audits in parallel
  const vtVerdicts = new Map<string, VTVerdict>();
  let auditData: Record<string, SkillAuditData> | null = null;
  let auditFailed = false; // true if audit was attempted but API was unreachable
  let vtEscalate = false;
  let auditEscalate: 'critical' | 'high' | null = null;

  await Promise.all([
    // VT lookups
    (async () => {
      if (options.vtKey && options.skillContents) {
        for (const [skillName, content] of options.skillContents) {
          try {
            const verdict = await checkSkillOnVT(content, options.vtKey);
            vtVerdicts.set(skillName, verdict);
            if (verdict.found && verdict.verdict === 'malicious') {
              vtEscalate = true;
            }
          } catch {
            // VT lookup failed — continue without it
          }
        }
      }
    })(),
    // skills.sh API audit
    (async () => {
      if (options.auditSource) {
        const data = await fetchAuditData(options.auditSource, skillNames);
        if (data) {
          auditData = data;
          auditEscalate = maxAuditRisk(skillNames, data);
        } else {
          auditFailed = true;
        }
      }
    })(),
  ]);

  const anyEscalation = vtEscalate || auditEscalate !== null;

  if (allFindings.length === 0 && !anyEscalation) {
    p.log.success(pc.green('Security scan passed — no issues found'));

    // Show VT results even when local scan is clean
    if (vtVerdicts.size > 0) {
      for (const [, verdict] of vtVerdicts) {
        displayVTVerdict(verdict);
      }
    }

    // Show audit results even when local scan is clean
    if (auditData && options.auditSource) {
      displayAuditResults(skillNames, auditData, options.auditSource);
    }

    if (auditFailed) {
      p.log.warn(
        pc.yellow('skills.sh audit unavailable — third-party risk data could not be fetched')
      );
    }

    // If URLs found in an otherwise clean skill, show them and prompt
    if (allUrls.length > 0) {
      return displayUrlsAndPrompt(allUrls, options);
    }

    return true;
  }

  // Compute overall max severity from local findings
  let overallMax: ScanSeverity = 'info';
  for (const f of allFindings) {
    if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[overallMax]) {
      overallMax = f.severity;
    }
  }

  // Display findings
  if (allFindings.length > 0) {
    console.log();
    p.log.warn(
      pc.yellow(
        `Security scan found ${allFindings.length} issue${allFindings.length !== 1 ? 's' : ''}`
      )
    );

    for (const result of results) {
      if (result.findings.length === 0) continue;

      if (results.length > 1) {
        p.log.message(pc.bold(`  ${result.skillName}:`));
      }

      for (const finding of result.findings) {
        const label = SEVERITY_LABELS[finding.severity];
        const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
        p.log.message(`  ${label} ${finding.message}`);
        p.log.message(pc.dim(`    ${location}: ${finding.matchedText}`));
      }
    }
  }

  // Show VT verdicts
  if (vtVerdicts.size > 0) {
    console.log();
    for (const [, verdict] of vtVerdicts) {
      displayVTVerdict(verdict);
    }
  }

  // Show skills.sh audit results
  if (auditData && options.auditSource) {
    console.log();
    displayAuditResults(skillNames, auditData, options.auditSource);
  }

  // Warn if audit was attempted but unavailable
  if (auditFailed) {
    p.log.warn(
      pc.yellow('skills.sh audit unavailable — third-party risk data could not be fetched')
    );
  }

  // Show URLs found in skill files
  if (allUrls.length > 0) {
    console.log();
    p.log.info(`External URLs found in skill files (${allUrls.length}):`);
    for (const url of allUrls) {
      p.log.message(pc.dim(`  ${url}`));
    }
  }

  console.log();

  // Escalate severity based on external signals
  if (vtEscalate) {
    overallMax = 'critical';
  }
  if (auditEscalate === 'critical') {
    overallMax = 'critical';
  } else if (auditEscalate === 'high' && SEVERITY_ORDER[overallMax] < SEVERITY_ORDER['high']) {
    overallMax = 'high';
  }

  // Decide based on severity
  if (SEVERITY_ORDER[overallMax] <= SEVERITY_ORDER['medium']) {
    // medium/low/info — auto-continue with note
    p.log.info(pc.dim('Low/medium severity findings — proceeding with installation'));
    return true;
  }

  // Critical or high: always prompt, --yes does not bypass
  if (overallMax === 'critical') {
    p.log.error(pc.red(pc.bold('Critical security issues detected. This skill may be malicious.')));
  } else {
    p.log.error(pc.red('High severity security issues detected.'));
  }

  const confirmed = await p.confirm({
    message: pc.yellow('Install anyway?'),
    initialValue: false,
  });
  if (p.isCancel(confirmed) || !confirmed) {
    return false;
  }
  return true;
}

/**
 * Display extracted URLs and prompt the user to confirm.
 * Used when the scan is clean but URLs are present.
 */
async function displayUrlsAndPrompt(urls: string[], options: PresentScanOptions): Promise<boolean> {
  console.log();
  p.log.info(`External URLs found in skill files (${urls.length}):`);
  for (const url of urls) {
    p.log.message(pc.dim(`  ${url}`));
  }

  if (options.yes) {
    p.log.info(pc.dim('Proceeding with installation (--yes flag set)'));
    return true;
  }

  const confirmed = await p.confirm({
    message: 'This skill references external URLs. Continue with installation?',
  });
  if (p.isCancel(confirmed) || !confirmed) {
    return false;
  }
  return true;
}
