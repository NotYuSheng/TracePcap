/** "Today 14:05", "3 Nov 2026 09:12": when someone, or a role, last signed in. */
export function signInTime(at: string): string {
  const d = new Date(at);
  const time = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  if (d.toDateString() === new Date().toDateString()) return `Today ${time}`;
  return `${d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })} ${time}`;
}
