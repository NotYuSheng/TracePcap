import type { DetectionRule } from './detectionRulesService';

/** A one-line summary of what a rule matches, e.g. "dstPort 4444 · payload: 1 regex". */
export function describeCriteria(r: DetectionRule): string {
  const parts = Object.entries(r.match ?? {})
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k} ${v}`);
  const pc = r.payloadContains?.length ?? 0;
  const re = r.payloadRegex?.length ?? 0;
  if (pc || re) {
    const bits = [
      pc ? `${pc} byte pattern${pc > 1 ? 's' : ''}` : '',
      re ? `${re} regex${re > 1 ? 'es' : ''}` : '',
    ]
      .filter(Boolean)
      .join(', ');
    parts.push(`payload: ${bits}${r.matchAll && pc + re > 1 ? ' (all)' : ''}`);
  }
  return parts.join(' · ') || 'no criteria';
}
