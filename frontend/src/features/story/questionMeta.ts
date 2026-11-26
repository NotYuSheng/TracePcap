/** Friendly label + icon per standard-question key; unknown keys fall back to the raw key. */
export const QUESTION_META: Record<string, { label: string; icon: string }> = {
  victim: { label: 'Victim host', icon: 'bi-pc-display' },
  c2: { label: 'Command & control', icon: 'bi-broadcast-pin' },
  malware: { label: 'Malware', icon: 'bi-bug' },
  'signed-in-user': { label: 'Signed-in user', icon: 'bi-person-badge' },
  'data-transfer': { label: 'Bulk transfer', icon: 'bi-arrow-up-right-circle' },
  'remote-access': { label: 'Remote-access tool', icon: 'bi-display' },
  'lateral-movement': { label: 'Lateral movement', icon: 'bi-diagram-2' },
  'kerberos-attack': { label: 'Kerberos attack', icon: 'bi-key' },
  downloads: { label: 'Downloaded file', icon: 'bi-file-earmark-arrow-down' },
};
