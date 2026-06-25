/// <reference types="vite/client" />

declare const __APP_VERSION__: string;

declare module 'virtual:world-map' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const topology: any;
  export default topology;
}
