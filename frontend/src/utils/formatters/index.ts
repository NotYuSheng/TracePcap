const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const;

/**
 * Human-readable byte size. The single definition (#733).
 *
 * Seven of these existed, each with its own ceiling. Two indexed past the end of their unit
 * array and rendered "1.0 undefined"; the others silently topped out, so a 2TB capture read
 * as "2048.0 GB". Production captures reach tens of TB, so both were reachable.
 *
 * The index is clamped rather than the unit list merely extended: an exabyte would otherwise
 * reintroduce the same bug at the next boundary.
 */
export const formatBytes = (bytes: number): string => {
  if (!Number.isFinite(bytes)) return '0 B';
  const magnitude = Math.abs(bytes);
  if (magnitude === 0) return '0 B';

  const k = 1024;
  const i = Math.min(Math.floor(Math.log(magnitude) / Math.log(k)), BYTE_UNITS.length - 1);
  const value = magnitude / Math.pow(k, i);
  // Whole bytes have no fractional part worth showing; anything larger is a rounded figure.
  const rendered = i === 0 ? String(value) : value.toFixed(2);
  return `${bytes < 0 ? '-' : ''}${rendered} ${BYTE_UNITS[i]}`;
};

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const MONTH_MS = 30.44 * DAY_MS;
const YEAR_MS = 365.25 * DAY_MS;

/** "1 day", "3 days"; `many` for an irregular plural ("category is" / "categories are"). */
export const plural = (n: number, one: string, many: string = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const oneDecimal = (n: number) => Math.round(n * 10) / 10;

/**
 * A length of time in the one unit that reads best: "45 s", "26 min", "5.2 h", "17 days",
 * "5 months", "16.8 years". For a capture's span, where "147438.8 h" would mean nothing.
 */
export const formatSpan = (ms: number): string => {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s} s`;
  if (s < 90 * 60) return `${Math.round(s / 60)} min`;
  if (ms < 48 * HOUR_MS) return `${oneDecimal(ms / HOUR_MS)} h`;
  if (ms < 60 * DAY_MS) return plural(Math.round(ms / DAY_MS), 'day');
  if (ms < 2 * YEAR_MS) return plural(Math.round(ms / MONTH_MS), 'month');
  return plural(oneDecimal(ms / YEAR_MS), 'year');
};

/**
 * Format duration in milliseconds to human-readable format
 * @param ms - Duration in milliseconds
 * @returns Formatted string (e.g., "2m 30s")
 */
export const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${ms}ms`;
  // Past two days, "6143h 12m" stops meaning anything: switch to days, months, years.
  if (ms >= 48 * HOUR_MS) return formatSpan(ms);

  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m`;
  }

  if (minutes > 0) {
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  }

  return `${seconds}s`;
};

/**
 * Format timestamp to readable date/time
 * @param timestamp - Unix timestamp in milliseconds
 * @returns Formatted string (e.g., "31 Jan 2026, 14:30:45")
 */
export const formatTimestamp = (timestamp: number): string => {
  const date = new Date(timestamp);
  return date.toLocaleString('en-GB', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
};

/**
 * Format timestamp to time only
 * @param timestamp - Unix timestamp in milliseconds
 * @returns Formatted string (e.g., "14:30:45")
 */
export const formatTime = (timestamp: number): string => {
  const date = new Date(timestamp);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
};

/**
 * Format number with thousand separators
 * @param num - Number to format
 * @returns Formatted string (e.g., "125,432")
 */
export const formatNumber = (num: number): string => {
  return num.toLocaleString('en-US');
};

/**
 * Format file size from bytes
 * @param size - Size in bytes
 * @returns Formatted string
 */
export const formatFileSize = (size: number): string => {
  return formatBytes(size);
};

/**
 * Format protocol name (uppercase)
 * @param protocol - Protocol string
 * @returns Uppercase protocol name
 */
export const formatProtocol = (protocol: string): string => {
  return protocol.toUpperCase();
};

/**
 * Format IP address with port
 * @param ip - IP address
 * @param port - Port number (optional)
 * @returns Formatted string (e.g., "192.168.1.1:80")
 */
export const formatIpPort = (ip: string, port?: number): string => {
  if (!port) return ip;
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
};

/**
 * Format percentage
 * @param value - Decimal value (0-1)
 * @param decimals - Number of decimal places (default: 1)
 * @returns Formatted string (e.g., "45.5%")
 */
export const formatPercentage = (value: number, decimals: number = 1): string => {
  return `${(value * 100).toFixed(decimals)}%`;
};

/** A ratio (0–1) as a whole percent, without the sign: 0.457 → 46. */
export const wholePercent = (ratio: number): number => Math.round(ratio * 100);

/** A chart's bin width in seconds, compactly: "30s", "5m", "1m 30s", "2h", "1h 15m", "3d". */
export const formatInterval = (secs: number): string => {
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (secs < 3600) return s === 0 ? `${m}m` : `${m}m ${s}s`;
  const h = Math.floor(secs / 3600);
  const rem = Math.floor((secs % 3600) / 60);
  if (secs < 86400) return rem === 0 ? `${h}h` : `${h}h ${rem}m`;
  return `${Math.floor(secs / 86400)}d`;
};
