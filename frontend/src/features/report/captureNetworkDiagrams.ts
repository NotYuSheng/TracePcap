/**
 * Captures both network diagram layouts by rendering the real NetworkGraph
 * React component into a visible-but-covered container and screenshotting it
 * with html-to-image.
 *
 * Why html-to-image:
 *   html-to-image uses SVG foreignObject serialisation which handles mixed
 *   HTML/canvas content correctly.
 *
 * Why skipFonts:true:
 *   html-to-image re-fetches every @font-face file to embed it inline.  The
 *   Bootstrap Icons font is bundled by Vite with hashed asset URLs that fail
 *   when re-fetched (CORS / wrong origin).  Skipping font embedding lets the
 *   capture succeed; labels and colours are preserved.
 *
 * Why visible container + scrim (and not any of the obvious alternatives):
 *   html-to-image captures what the browser actually painted, so the container
 *   must be on-screen, opaque and laid out.  Every way of hiding it breaks the
 *   capture, each differently — all three have been tried:
 *     - opacity:0                -> transparent PNG (html-to-image respects opacity)
 *     - display/visibility:hidden -> no layout, so an empty box
 *     - off-screen positioning    -> not painted, so a blank white image
 *   So it stays visible at z-index 9999 and a scrim at 10000 covers it.
 *
 * Why the scrim is dark, not white:
 *   It used to be solid #fff, which is what users saw as a flash on Download
 *   Report — a white sheet over a dark app, replaced a beat later by the caller's
 *   dark progress modal (z-index 10001): "white background, then opaque".  The
 *   scrim now matches that modal's own rgba(0,0,0,0.55), so whichever paints
 *   first the screen simply dims once and stays dimmed until the PDF is ready.
 *
 * Why forceLight rather than a CSS override:
 *   The PDF wants white diagrams whatever the user's theme.  NetworkGraph picks its
 *   colours in JavaScript (theme store + matchMedia), so no CSS on an ancestor reaches
 *   them — the old code set data-theme="light" on <html> and it never worked: the
 *   diagram captured in the user's theme regardless, and the only thing the override
 *   achieved was strobing the whole app light/dark through two sequential captures.
 *   The component takes an explicit forceLight prop instead.
 */

import { createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { toPng } from 'html-to-image';
import { NetworkGraph } from '@/components/network/NetworkGraph/NetworkGraph';
import type { GraphNode, GraphEdge } from '@/features/network/types';
const CAPTURE_W = 1400;
const CAPTURE_H = 860;

let captureSeq = 0;

async function captureLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  layoutType: 'circular' | 'hierarchicalTd'
): Promise<string> {
  return new Promise((resolve, reject) => {
    const id = `__nr-capture-${++captureSeq}`;

    // Scrim that hides the capture container from the user.
    //
    // It has to exist: the container underneath must stay painted for html-to-image to see it.
    // It used to be solid WHITE, which is what users reported as "white background, then opaque" —
    // a white sheet dropped over a dark app, then replaced by the progress modal's dark scrim a
    // beat later. Matching the modal's own scrim makes the two indistinguishable: whichever paints
    // first, the screen dims once and stays dimmed until the report is ready.
    const overlay = document.createElement('div');
    overlay.style.cssText =
      'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,0.55);pointer-events:none';

    // Capture container — on-screen and fully painted, because html-to-image captures what the
    // browser actually rendered. It cannot be hidden: opacity:0 yields a transparent PNG, and
    // display/visibility/off-screen stop it being laid out or painted. It is covered, not hidden.
    const container = document.createElement('div');
    container.id = id;
    container.style.cssText = [
      'position:fixed',
      'top:0',
      'left:0',
      `width:${CAPTURE_W}px`,
      `height:${CAPTURE_H}px`,
      'z-index:9999',
      'overflow:hidden',
      'background:#fff',
    ].join(';');

    // Override the component's 70vh height so it fills the capture area.
    const styleEl = document.createElement('style');
    styleEl.textContent = `#${id} .network-graph-wrapper { height:${CAPTURE_H}px !important; }`;

    document.head.appendChild(styleEl);
    document.body.appendChild(overlay);
    document.body.appendChild(container);

    const root = createRoot(container);
    let done = false;

    const cleanup = () => {
      root.unmount();
      container.remove();
      overlay.remove();
      styleEl.remove();
    };

    const handleLayoutComplete = () => {
      if (done) return;
      done = true;

      // Wait for Sigma to fully settle: ForceAtlas2 convergence and any
      // internal async paint passes all need to complete before we snapshot.
      // rAFs alone are not enough for force-directed layouts with many edges —
      // a short setTimeout gives the browser time to finish all pending work.
      setTimeout(
        () =>
          requestAnimationFrame(async () => {
            try {
              const dataUrl = await toPng(container, {
                width: CAPTURE_W,
                height: CAPTURE_H,
                pixelRatio: 6,
                // Skip re-fetching web fonts (Bootstrap Icons) — those fetches
                // fail when Vite-bundled with hashed asset URLs.  Edge lines,
                // labels and colours are all captured; only icon glyphs are
                // absent.
                skipFonts: true,
              });
              cleanup();
              resolve(dataUrl.split(',')[1]);
            } catch (err) {
              console.error('[captureNetworkDiagrams] toPng failed:', err);
              cleanup();
              reject(err);
            }
          }),
        500
      );
    };

    root.render(
      createElement(NetworkGraph, {
        nodes,
        edges,
        layoutType,
        onLayoutComplete: handleLayoutComplete,
        // The PDF is white whatever the user's theme; the component picks its colours in JS, so
        // this has to be a prop.
        forceLight: true,
      })
    );

    // Safety valve — 30 s should be ample even for large captures.
    setTimeout(() => {
      if (!done) {
        done = true;
        cleanup();
        reject(new Error(`Network diagram capture timed out (${layoutType})`));
      }
    }, 30_000);
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface DiagramImages {
  forceDirected: string; // base64 PNG
  hierarchical: string; // base64 PNG
}

/**
 * Captures both ELK layouts for the given pre-filtered nodes and edges.
 * The caller is responsible for passing exactly the nodes/edges currently
 * visible on screen so the report matches what the user sees.
 */
export async function captureNetworkDiagrams(
  nodes: GraphNode[],
  edges: GraphEdge[]
): Promise<DiagramImages> {
  // Sequential — captures are serialised to avoid two Sigma instances
  // competing for the same DOM container pool.
  const forceDirected = await captureLayout(nodes, edges, 'circular');
  const hierarchical = await captureLayout(nodes, edges, 'hierarchicalTd');

  return { forceDirected, hierarchical };
}
