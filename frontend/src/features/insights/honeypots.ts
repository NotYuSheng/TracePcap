import type { HoneypotHost } from '@/types';

/** A honeypot verdict, not "Not a honeypot" and not undetermined. */
export function isHoneypot(h: HoneypotHost): boolean {
  return !!h.label && h.label !== 'Not a honeypot';
}

/**
 * The hosts worth a line in the summary: every honeypot, and every host a signature points at
 * that its signals don't settle. A host an analyst marked "Not a honeypot" needs no line.
 */
export function honeypotLines(hosts: HoneypotHost[]): HoneypotHost[] {
  return hosts.filter(h => isHoneypot(h) || h.label === null);
}

/** "198.51.100.45 is a Dionaea honeypot" or "198.51.100.22 may be a Cowrie honeypot". */
export function honeypotText(h: HoneypotHost): string {
  if (h.described) return h.described;
  return `${h.host} may be a ${h.honeypot ? `${h.honeypot} ` : ''}honeypot`;
}

/** "inferred, 95%", "set by an analyst", or why it's undetermined ("one signal only, …"). */
export function honeypotGrade(h: HoneypotHost): string {
  if (!h.label) return h.reason ?? 'not settled';
  if (h.basis === 'HUMAN') return 'set by an analyst';
  return `inferred${h.contested ? ', contested' : ''}, ${h.confidence}%`;
}
