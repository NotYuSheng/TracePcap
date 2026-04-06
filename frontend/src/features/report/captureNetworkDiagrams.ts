/**
 * Captures both ELK network diagram layouts by rendering the real NetworkGraph
 * React component into a visible-but-covered container and screenshotting it
 * with html-to-image.
 *
 * Why html-to-image (not html2canvas):
 *   html2canvas does not reliably capture SVG elements, and ReactFlow renders
 *   all edges as SVG.  html-to-image uses SVG foreignObject serialisation which
 *   handles the ReactFlow SVG+HTML mix correctly.
 *
 * Why skipFonts:true:
 *   html-to-image re-fetches every @font-face file to embed it inline.  The
 *   Bootstrap Icons font is bundled by Vite with hashed asset URLs that fail
 *   when re-fetched (CORS / wrong origin).  Skipping font embedding lets the
 *   capture succeed; node-type icons inside the circles will be blank glyphs,
 *   but all topology edges, labels and colours are preserved.
 *
 * Why visible container + overlay:
 *   Both html-to-image and html2canvas respect CSS opacity.  Using opacity:0
 *   produces a fully transparent PNG.  Instead the container sits at z-index
 *   9999 (fully opaque, fully painted) while a solid white overlay at z-index
 *   10000 hides it from the user.  html-to-image targets the container element
 *   directly and ignores the overlay above it.
 */

import { createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { toPng } from 'html-to-image';
import { conversationService } from '@/features/conversation/services/conversationService';
import { networkService } from '@/features/network/services/networkService';
import { NetworkGraph } from '@/components/network/NetworkGraph/NetworkGraph';
import { CONVERSATION_LIMIT_ENABLED } from '@/features/network/hooks/useNetworkData';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import type { AnalysisSummary } from '@/types';

// Match the same conversation cap the Network Diagram page uses so the report
// shows identical edges.  If the env flag disables the limit, capture all.
const MAX_CONVERSATIONS = CONVERSATION_LIMIT_ENABLED ? 500 : Infinity;
const CAPTURE_W = 1400;
const CAPTURE_H = 860;

let captureSeq = 0;

async function captureLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  layoutType: 'forceDirected2d' | 'hierarchicalTd'
): Promise<string> {
  // Force light mode on the html element for the duration of the capture so
  // the PDF diagram is always rendered on a white background regardless of
  // the user's current theme setting.
  const prevTheme = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', 'light');

  return new Promise((resolve, reject) => {
    const id = `__nr-capture-${++captureSeq}`;

    // Solid white overlay — hides the container from the user while it renders.
    const overlay = document.createElement('div');
    overlay.style.cssText =
      'position:fixed;inset:0;z-index:10000;background:#fff;pointer-events:none';

    // Capture container — on-screen, fully opaque so the capture library gets
    // real pixels.  Covered by the overlay above.
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
    styleEl.textContent = `#${id} .network-graph-container { height:${CAPTURE_H}px !important; }`;

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
      // Restore the user's original theme after capture completes.
      if (prevTheme) {
        document.documentElement.setAttribute('data-theme', prevTheme);
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
    };

    const handleLayoutComplete = () => {
      if (done) return;
      done = true;

      // Wait for ReactFlow to fully settle: fitView, edge routing and any
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

export async function captureNetworkDiagrams(
  fileId: string,
  analysisSummary?: AnalysisSummary
): Promise<DiagramImages> {
  const response = await conversationService.getConversations(fileId, {
    ip: '',
    port: '',
    payloadContains: '',
    protocols: [],
    l7Protocols: [],
    apps: [],
    categories: [],
    hasRisks: false,
    fileTypes: [],
    riskTypes: [],
    customSignatures: [],
    deviceTypes: [],
    countries: [],
    sortBy: '',
    sortDir: 'asc',
    page: 1,
    pageSize: 10000,
  });

  let hostClassifications;
  try {
    hostClassifications = await conversationService.getHostClassifications(fileId);
  } catch {
    /* optional — best effort */
  }

  const { nodes, edges } = networkService.buildNetworkGraph(
    response.data,
    analysisSummary,
    MAX_CONVERSATIONS,
    hostClassifications
  );

  // Sequential — both layouts share the module-level ELK singleton inside
  // NetworkGraph.tsx; running them in parallel risks a layout race condition.
  const forceDirected = await captureLayout(nodes, edges, 'forceDirected2d');
  const hierarchical = await captureLayout(nodes, edges, 'hierarchicalTd');

  return { forceDirected, hierarchical };
}
