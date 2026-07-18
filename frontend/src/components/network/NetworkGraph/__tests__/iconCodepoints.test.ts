import { deviceTypeIcon } from '@/utils/deviceType';
import { NODE_TYPE_ICONS, DEVICE_TYPE_ICONS } from '../nodeIcons';
import iconCodepointsByName from 'bootstrap-icons/font/bootstrap-icons.json';
import nodeIconsSrc from '../nodeIcons.ts?raw';

/**
 * nodeIcons.ts hardcodes raw Bootstrap Icon codepoints (Sigma renders nodes in WebGL and
 * can't use CSS classes), each with a trailing `// bi-xxx` comment naming the class it was
 * copied from. That copy has drifted before (#495: IoT drew a lightbulb, Mobile a patch-minus).
 * This test verifies every codepoint still matches its named class in the installed
 * bootstrap-icons package, and that DEVICE_TYPE_ICONS still agrees with deviceTypeIcon(),
 * the class-name source the legend renders from.
 *
 * <p>Sourced from bootstrap-icons.json (name → decimal codepoint) rather than the .css file:
 * a plain JSON import works identically under Vite and vitest, whereas vitest.config disables
 * CSS processing (`css: false`), which silently empties out `?raw` imports of .css files.
 */

const classToCodepoint = new Map<string, string>(
  Object.entries(iconCodepointsByName).map(([name, codepoint]) => [
    `bi-${name}`,
    (codepoint as number).toString(16).padStart(4, '0'),
  ])
);

const entries = [...nodeIconsSrc.matchAll(/'\\u([0-9a-fA-F]{4})',\s*\/\/\s*(bi-[\w-]+)/g)];

describe('nodeIcons.ts codepoints match their named Bootstrap Icon class', () => {
  it('finds codepoint/class comment pairs to check (sanity check the regex still matches the file)', () => {
    expect(entries.length).toBeGreaterThan(0);
  });

  it.each(entries.map(m => [m[2], m[1]] as const))('%s resolves to \\u%s', (className, codepoint) => {
    expect(classToCodepoint.get(className)).toBe(codepoint);
  });
});

describe('DEVICE_TYPE_ICONS matches the legend\'s deviceTypeIcon() class names', () => {
  it.each(Object.keys(DEVICE_TYPE_ICONS) as (keyof typeof DEVICE_TYPE_ICONS)[])('%s', (deviceType) => {
    const legendClass = deviceTypeIcon(deviceType);
    const expectedCodepoint = classToCodepoint.get(legendClass);
    expect(expectedCodepoint).toBeDefined();
    expect(DEVICE_TYPE_ICONS[deviceType]).toBe(String.fromCharCode(parseInt(expectedCodepoint!, 16)));
  });
});

describe('NODE_TYPE_ICONS and DEVICE_TYPE_ICONS have no unexpected extra keys', () => {
  it('every table entry is present among the parsed comment pairs', () => {
    const allValues = new Set([...Object.values(NODE_TYPE_ICONS), ...Object.values(DEVICE_TYPE_ICONS)]);
    const commentValues = new Set(entries.map(m => String.fromCharCode(parseInt(m[1], 16))));
    for (const v of allValues) {
      expect(commentValues.has(v)).toBe(true);
    }
  });
});
