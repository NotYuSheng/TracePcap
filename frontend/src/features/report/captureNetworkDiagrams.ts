/**
 * Captures both graph layout views by rendering the real NetworkGraph
 * React component into a visible-but-covered container and screenshotting it.
 *
 * React Flow renders via SVG/CSS (no WebGL), so html-to-image works directly.
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
  layoutType: 'forceDirected2d' | 'hierarchicalTd'
): Promise<string> {
  // Force light mode so the PDF is always on a white background.
  const prevTheme = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', 'light');

  return new Promise((resolve, reject) => {
    const id = `__nr-capture-${++captureSeq}`;

    // Solid white overlay — hides the render container from the user.
    const overlay = document.createElement('div');
    overlay.style.cssText =
      'position:fixed;inset:0;z-index:10000;background:#fff;pointer-events:none';

    // Capture container — on-screen and fully opaque so React Flow paints.
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

    document.body.appendChild(overlay);
    document.body.appendChild(container);

    const root = createRoot(container);
    let done = false;

    const cleanup = () => {
      root.unmount();
      container.remove();
      overlay.remove();
      if (prevTheme) {
        document.documentElement.setAttribute('data-theme', prevTheme);
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
    };

    const handleLayoutComplete = () => {
      if (done) return;
      done = true;

      // Give React Flow a frame to finish its final render before screenshotting.
      requestAnimationFrame(() => {
        setTimeout(async () => {
          try {
            const flowEl = container.querySelector('.react-flow') as HTMLElement;
            if (!flowEl) throw new Error('react-flow element not found in capture container');

            const dataUrl = await toPng(flowEl, {
              pixelRatio: 2,
              backgroundColor: '#ffffff',
              width: CAPTURE_W,
              height: CAPTURE_H,
            });
            cleanup();
            resolve(dataUrl.replace(/^data:image\/png;base64,/, ''));
          } catch (err) {
            console.error('[captureNetworkDiagrams] html-to-image failed:', err);
            cleanup();
            reject(err);
          }
        }, 300);
      });
    };

    root.render(
      createElement(NetworkGraph, {
        nodes,
        edges,
        layoutType,
        captureMode: true,
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
  hierarchical:  string; // base64 PNG
}

/**
 * Captures both layouts for the given pre-filtered nodes and edges.
 * Sequential — avoids layout conflicts between renders.
 */
export async function captureNetworkDiagrams(
  nodes: GraphNode[],
  edges: GraphEdge[]
): Promise<DiagramImages> {
  const forceDirected = await captureLayout(nodes, edges, 'forceDirected2d');
  const hierarchical  = await captureLayout(nodes, edges, 'hierarchicalTd');
  return { forceDirected, hierarchical };
}
