/**
 * Where "In the docs →" links point: the published documentation. A rebrand without public docs
 * sets this to '' and the links disappear. Links open in a new tab; an offline install simply
 * can't follow them, which is why nothing depends on them.
 */
export const DOCS_BASE_URL = 'https://notyusheng.github.io/TracePcap';

/** A docs page, e.g. docsUrl('features/story-mode', 'deterministic-findings'); null when there are no docs. */
export function docsUrl(page: string, anchor?: string): string | null {
  if (!DOCS_BASE_URL) return null;
  return `${DOCS_BASE_URL}/${page}.html${anchor ? `#${anchor}` : ''}`;
}
