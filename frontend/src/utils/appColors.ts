const APP_COLORS: Record<string, string> = {
  Zoom: '#2D8CFF',
  WhatsApp: '#25D366',
  Telegram: '#2AABEE',
  Signal: '#3A76F0',
  Discord: '#5865F2',
  Teams: '#6264A7',
  Skype: '#00AFF0',
  Viber: '#7360F2',
  WeChat: '#07C160',
  YouTube: '#FF0000',
  Netflix: '#E50914',
  Spotify: '#1DB954',
  TikTok: '#010101',
  Instagram: '#E1306C',
  Facebook: '#1877F2',
  Twitter: '#1DA1F2',
};

const DEFAULT_APP_COLOR = '#6f42c1';

export function getAppColor(appName: string): string {
  return APP_COLORS[appName] ?? DEFAULT_APP_COLOR;
}

export { APP_COLORS };
