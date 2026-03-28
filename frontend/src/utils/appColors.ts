import ColorHash from 'color-hash';

const colorHash = new ColorHash({ lightness: 0.45, saturation: 0.6 });

export function getAppColor(appName: string): string {
  return colorHash.hex(appName);
}

export function getCategoryColor(category: string): string {
  return colorHash.hex(category);
}

/**
 * Returns '#000' or '#fff' depending on which has better contrast
 * against the given hex background colour (uses WCAG relative luminance).
 */
export function getTextColor(hexBackground: string): string {
  const r = parseInt(hexBackground.slice(1, 3), 16);
  const g = parseInt(hexBackground.slice(3, 5), 16);
  const b = parseInt(hexBackground.slice(5, 7), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.5 ? '#000' : '#fff';
}
