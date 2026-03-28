import ColorHash from 'color-hash';

const colorHash = new ColorHash({ lightness: 0.45, saturation: 0.6 });

export function getAppColor(appName: string): string {
  return colorHash.hex(appName);
}

export function getCategoryColor(category: string): string {
  return colorHash.hex(category);
}
