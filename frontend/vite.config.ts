/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from 'vite'
import { configDefaults } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'
import { execSync } from 'child_process'

// The VITE_APP_VERSION build arg is the primary source: the Docker build context excludes
// .git, so the git call below only ever resolves on a bare-metal build.
//
// `isBuild` gates the failure: only a build produces a shippable artifact, so only a build
// must refuse to proceed without a real version (#500). The dev server and vitest compile
// __APP_VERSION__ for a process that is never deployed, so they degrade to a label instead
// of breaking in .git-less checkouts (zip downloads, test containers).
function getAppVersion(isBuild: boolean, envFallback?: string): string {
  // Vite's loadEnv populates the `env` object but not process.env, so accept the loaded value.
  const supplied = (envFallback || process.env.VITE_APP_VERSION || '').trim();
  if (supplied) return supplied;

  try {
    // stdio: silence git's stderr ("fatal: not a git repository") in non-git build contexts.
    const described = execSync('git describe --tags --always', {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (described) return described;
  } catch {
    // Fall through — either fail the build, or label a non-shipping process below.
  }

  if (!isBuild) return 'local-dev';

  throw new Error(
    'Cannot resolve app version: VITE_APP_VERSION was not supplied and `git describe` is ' +
      'unavailable. Pass the VITE_APP_VERSION build arg (see docker-compose.yml).'
  );
}

const VALID_RESOLUTIONS = ['110m', '50m', '10m'] as const;
type MapResolution = (typeof VALID_RESOLUTIONS)[number];

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd());
  const rawResolution = env.VITE_MAP_RESOLUTION ?? '50m';
  const resolution: MapResolution = (VALID_RESOLUTIONS as readonly string[]).includes(rawResolution)
    ? (rawResolution as MapResolution)
    : '50m';
  const mapFile = path.resolve(__dirname, `src/assets/geo/world-${resolution}.json`);

  const worldMapPlugin = {
    name: 'world-map-resolution',
    resolveId(id: string) {
      if (id === 'virtual:world-map') return '\0virtual:world-map';
    },
    load(id: string) {
      if (id === '\0virtual:world-map') {
        return `import data from ${JSON.stringify(mapFile)}; export default data;`;
      }
    },
  };

  return {
    define: {
      __APP_VERSION__: JSON.stringify(getAppVersion(command === 'build', env.VITE_APP_VERSION)),
    },
    plugins: [react(), worldMapPlugin],
    resolve: {
      alias: {
        // elkjs default entry uses web workers which don't work in Vite's browser build.
        // Redirect to the self-contained bundled version that runs synchronously.
        'elkjs': path.resolve(__dirname, 'node_modules/elkjs/lib/elk.bundled.js'),
        '@': path.resolve(__dirname, './src'),
        '@components': path.resolve(__dirname, './src/components'),
        '@pages': path.resolve(__dirname, './src/pages'),
        '@features': path.resolve(__dirname, './src/features'),
        '@hooks': path.resolve(__dirname, './src/hooks'),
        '@utils': path.resolve(__dirname, './src/utils'),
        '@services': path.resolve(__dirname, './src/services'),
        '@store': path.resolve(__dirname, './src/store'),
        '@types': path.resolve(__dirname, './src/types'),
        '@assets': path.resolve(__dirname, './src/assets'),
      },
    },
    server: {
      port: 3000,
      proxy: {
        '/api': {
          target: 'http://localhost:8080',
          changeOrigin: true,
          secure: false,
        },
      },
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: './src/test/setup.ts',
      css: false,
      exclude: [...configDefaults.exclude, 'e2e/**'],
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
      rollupOptions: {
        output: {
          manualChunks: {
            'react-vendor': ['react', 'react-dom', 'react-router-dom'],
            'viz-vendor': ['recharts', 'd3', '@xyflow/react'],
            'sgds-vendor': ['@govtechsg/sgds-react', '@govtechsg/sgds'],
          },
        },
      },
    },
  };
})
