/**
 * Turns an audit entry's before/after values into a short, readable list of what changed (#915):
 * only the fields that differ on an update, every field on a creation or removal. Nested values
 * are flattened to paths ("Match › Dst port"); bookkeeping fields (ids, internal timestamps,
 * version counters) are left out.
 */

export type ChangeKind = 'added' | 'removed' | 'changed';

export interface FieldChange {
  /** Readable path: "Match › Dst port". */
  field: string;
  kind: ChangeKind;
  before?: string;
  after?: string;
}

/** Bookkeeping that every record carries and nobody reads in an audit trail. */
const HIDDEN = new Set(['id', 'createdAt', 'updatedAt', 'labeledAt', 'version', 'copiedAt']);

/** "dstPort" → "Dst port", "overridesDefault" → "Overrides default", "macA" → "MAC A". */
export function humanize(key: string): string {
  if (/^(type|subnet|network|domain):/.test(key)) return groupIdText(key);
  if (/[.:/]/.test(key)) return key; // an address, a CIDR, an id: keep as is
  const words = key
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .trim()
    .split(/\s+/)
    .map(w => w.toLowerCase());
  const known: Record<string, string> = { mac: 'MAC', ip: 'IP', cidr: 'CIDR', ttl: 'TTL', dns: 'DNS', dhcp: 'DHCP', vlan: 'VLAN', id: 'ID' };
  const out = words.map(w => known[w] ?? (w.length === 1 ? w.toUpperCase() : w));
  if (out.length && !known[words[0]]) out[0] = out[0].charAt(0).toUpperCase() + out[0].slice(1);
  return out.join(' ');
}

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/;

/**
 * A network map group id (#649) in words: `type:vlan:20:10.20.20.0/24:Laptops and desktops` →
 * "Laptops and desktops · 10.20.20.0/24". Anything else comes back unchanged.
 */
export function groupIdText(v: string): string {
  // The network key can hold colons (vlan:20), so the subnet is found by its shape.
  const SUBNET = '(\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+|[0-9a-f:]+::/64|No IP address)';
  let m = new RegExp(`^type:.*?:${SUBNET}:(.+)$`).exec(v);
  if (m) return `${m[2]} · ${m[1]}`;
  m = new RegExp(`^subnet:.*?:${SUBNET}$`).exec(v);
  if (m) return m[1];
  m = /^network:(.+)$/.exec(v);
  if (m) return m[1] === 'other' ? 'Other local addresses' : `network ${m[1]}`;
  m = /^domain:(.+)$/.exec(v);
  if (m) return m[1] === 'none' ? 'No hostname' : m[1];
  return v;
}

/** A leaf value as text: Yes/No, local times, network map groups in words, the rest as it is. */
export function show(v: unknown): string {
  if (v === null || v === undefined || v === '') return '—';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'string' && /^(type|subnet|network|domain):/.test(v)) return groupIdText(v);
  if (typeof v === 'string' && ISO_TIME.test(v)) {
    const d = new Date(v);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
  }
  if (Array.isArray(v)) return v.length ? v.map(show).join(', ') : '—';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

/** Flattens a value into path → leaf text. Arrays of records are keyed by their id or name. */
export function flatten(value: unknown, path: string[] = [], out = new Map<string, string>()): Map<string, string> {
  if (value === null || value === undefined) return out;
  if (Array.isArray(value)) {
    if (value.every(x => x !== null && typeof x === 'object' && !Array.isArray(x))) {
      value.forEach((item, i) => {
        const rec = item as Record<string, unknown>;
        const key = String(rec.name ?? rec.label ?? rec.id ?? i + 1);
        flatten(rec, [...path, key], out);
      });
      if (value.length === 0 && path.length) out.set(path.join(' › '), '—');
      return out;
    }
    if (path.length) out.set(path.join(' › '), show(value));
    return out;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([k]) => !HIDDEN.has(k));
    if (entries.length === 0 && path.length) out.set(path.join(' › '), '—');
    for (const [k, v] of entries) flatten(v, [...path, humanize(k)], out);
    return out;
  }
  if (path.length) out.set(path.join(' › '), show(value));
  return out;
}

/** What changed between two values, field by field. */
export function diffValues(before: unknown, after: unknown): FieldChange[] {
  const a = flatten(before);
  const b = flatten(after);
  const out: FieldChange[] = [];
  const isEmpty = (v: string | undefined) => v === undefined || v === '—';
  if (before == null) {
    b.forEach((v, field) => !isEmpty(v) && out.push({ field, kind: 'added', after: v }));
    return out;
  }
  if (after == null) {
    a.forEach((v, field) => !isEmpty(v) && out.push({ field, kind: 'removed', before: v }));
    return out;
  }
  const fields = [...new Set([...a.keys(), ...b.keys()])];
  for (const field of fields) {
    const x = a.get(field);
    const y = b.get(field);
    if (x === y || (isEmpty(x) && isEmpty(y))) continue;
    if (isEmpty(x)) out.push({ field, kind: 'added', after: y });
    else if (isEmpty(y)) out.push({ field, kind: 'removed', before: x });
    else out.push({ field, kind: 'changed', before: x, after: y });
  }
  return out;
}

/** "detection-rule.update" → "Detection rule · update"; "network-device.link.same" → "Network device · link same". */
export function describeAction(action: string): string {
  const [subject, ...rest] = action.split('.');
  const what = humanize(subject);
  return rest.length ? `${what} · ${rest.join(' ')}` : what;
}

// ── One line per entry, for the audit table ─────────────────────────────────────────────────────

/** The kinds of thing the audit log records, for its filter chips: label → target types. */
export const AUDIT_KINDS: { key: string; label: string; types: string[] }[] = [
  { key: 'rules', label: 'Rules', types: ['detection-rule'] },
  { key: 'maps', label: 'Maps', types: ['network-map'] },
  { key: 'devices', label: 'Devices', types: ['host-occupancy', 'network-device', 'host-classification'] },
  { key: 'addresses', label: 'Addresses', types: ['network-subnet', 'network-private-range', 'network-ip-org-rule', 'subnet', 'private-range', 'ip-org-rule'] },
  { key: 'access', label: 'Settings and access', types: ['system-setting', 'permission', 'network'] },
];

/** The kind of thing an entry is about, as a short tag. */
export function kindOf(targetType: string): string {
  const k = AUDIT_KINDS.find(x => x.types.includes(targetType));
  if (!k) return humanize(targetType);
  return { rules: 'Rule', maps: 'Map', devices: 'Device', addresses: 'Address', access: 'Setting' }[k.key] ?? k.label;
}

const VERBS: Record<string, string> = {
  create: 'Created', update: 'Changed', delete: 'Deleted', set: 'Set', reset: 'Reset', edit: 'Edited',
  undo: 'Undid', reapply: 'Re-applied', merge: 'Merged', split: 'Split', same: 'Linked as one device',
  'not-same': 'Marked as different devices', not_same: 'Marked as different devices', promote: 'Made global',
};

/** What the entry was about, by name: a rule's name, a label, a range, else the last part of its id. */
function subjectOf(before?: Record<string, unknown> | null, after?: Record<string, unknown> | null, targetId?: string | null): string {
  const v = { ...(before ?? {}), ...(after ?? {}) } as Record<string, unknown>;
  for (const k of ['name', 'label', 'cidr', 'ip', 'key']) if (typeof v[k] === 'string' && v[k]) return String(v[k]);
  if (typeof v.macA === 'string' && typeof v.macB === 'string') return `${v.macA} and ${v.macB}`;
  if (!targetId) return '';
  const last = targetId.split('/').pop() ?? targetId;
  return /^[0-9a-f-]{36}$/i.test(last) ? '' : last;
}

/** "Changed live_check_tcp: Enabled", "Created branch_smb", "Linked as one device 3a:… and 7e:…". */
/** A network map edit (#649) in words: what moved, what was added, renamed or noted. */
function summarizeMapEdit(before?: Record<string, unknown> | null, after?: Record<string, unknown> | null): string {
  const obj = (v: unknown) => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
  const list = (v: unknown) => (Array.isArray(v) ? (v as Record<string, unknown>[]) : []);
  const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  if (!after) {
    const b = before ?? {};
    const n = Object.keys(obj(b.placements)).length + list(b.groups).length + Object.keys(obj(b.names)).length + Object.keys(obj(b.notes)).length;
    return n ? `Reset the network map (${count(n, 'edit', 'edits')} dropped)` : 'Reset the network map';
  }
  const b = before ?? {};
  const parts: string[] = [];
  const keysChanged = (x: unknown, y: unknown) => {
    const a = obj(x);
    const c = obj(y);
    return [...new Set([...Object.keys(a), ...Object.keys(c)])].filter(k => a[k] !== c[k]);
  };
  const moved = keysChanged(b.placements, after.placements);
  if (moved.length) parts.push(`Moved ${count(moved.length, 'device', 'devices')}`);
  const beforeGroups = new Map(list(b.groups).map(g => [String(g.id), g]));
  const afterGroups = new Map(list(after.groups).map(g => [String(g.id), g]));
  for (const [id, g] of afterGroups) if (!beforeGroups.has(id)) parts.push(`Added the group “${String(g.name)}”`);
  for (const [id, g] of beforeGroups) if (!afterGroups.has(id)) parts.push(`Deleted the group “${String(g.name)}”`);
  const renamed = keysChanged(b.names, after.names);
  if (renamed.length) parts.push(`Renamed ${count(renamed.length, 'group', 'groups')}`);
  const noted = keysChanged(b.notes, after.notes);
  if (noted.length) parts.push(`Noted ${count(noted.length, 'group', 'groups')}`);
  if (!parts.length) return 'Edited the network map';
  const text = parts.join(', ');
  return text.charAt(0) + text.slice(1).replace(/(, )([A-Z])/g, (_m, sep, c) => sep + c.toLowerCase());
}

export function summarize(e: {
  action: string;
  targetId?: string | null;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
}): string {
  if (e.action.startsWith('network-map.')) return summarizeMapEdit(e.before, e.after);
  const verbKey = e.action.split('.').pop() ?? e.action;
  const verb = VERBS[verbKey] ?? humanize(verbKey);
  const subject = subjectOf(e.before, e.after, e.targetId);
  let text = subject ? `${verb} ${subject}` : verb;
  if (e.before && e.after) {
    const fields = [...new Set(diffValues(e.before, e.after).map(c => c.field.split(' › ')[0]))];
    if (fields.length) text += `: ${fields.slice(0, 3).join(', ')}${fields.length > 3 ? ` and ${fields.length - 3} more` : ''}`;
  }
  return text;
}
