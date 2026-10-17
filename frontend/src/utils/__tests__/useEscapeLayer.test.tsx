/**
 * Escape ownership across stacked popups (#535). The two rules under test are the ones the app
 * kept getting wrong: an Escape must close exactly *one* layer, and the one it closes must be the
 * one on top — including when the layer above is an SGDS/react-bootstrap modal, which handles the
 * key itself through its own `document` listener rather than through this stack.
 */
import { act, fireEvent, render } from '@testing-library/react';
import { useEffect, useRef, useState, type RefObject } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useEscapeLayer, useEscapeLayerRoot, __resetEscapeLayers } from '../useEscapeLayer';

afterEach(() => __resetEscapeLayers());

function pressEscape(): void {
  act(() => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
  });
}

/** A hand-rolled overlay: registers a layer and renders an element at `zIndex`. */
function Layer({ onEscape, zIndex, enabled = true }: { onEscape: () => void; zIndex: number; enabled?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEscapeLayer(onEscape, { enabled, ref });
  return <div ref={ref} data-testid="layer" style={{ position: 'fixed', zIndex }} />;
}

/**
 * Stand-in for a react-bootstrap modal: the same `.modal.show` markup, and the same
 * document-level (bubble phase) Escape listener @restart/ui installs.
 */
function ForeignModal({ onEscape, zIndex }: { onEscape: () => void; zIndex: number }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onEscape(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onEscape]);
  return <div className="modal show" style={{ position: 'fixed', zIndex }} />;
}

describe('useEscapeLayer', () => {
  it('closes the layer on Escape', () => {
    const onEscape = vi.fn();
    render(<Layer onEscape={onEscape} zIndex={1055} />);

    pressEscape();

    expect(onEscape).toHaveBeenCalledTimes(1);
  });

  it('ignores Escape while the layer is disabled', () => {
    const onEscape = vi.fn();
    render(<Layer onEscape={onEscape} zIndex={1055} enabled={false} />);

    pressEscape();

    expect(onEscape).not.toHaveBeenCalled();
  });

  it('unwinds nested layers one at a time, topmost first', () => {
    const closeOuter = vi.fn();
    const closeInner = vi.fn();
    function Nested() {
      const [innerOpen, setInnerOpen] = useState(false);
      return (
        <>
          <Layer onEscape={closeOuter} zIndex={1055} />
          <button onClick={() => setInnerOpen(true)}>open</button>
          {innerOpen && <Layer onEscape={() => { closeInner(); setInnerOpen(false); }} zIndex={1065} />}
        </>
      );
    }
    const { getByText } = render(<Nested />);
    fireEvent.click(getByText('open'));

    pressEscape();
    expect(closeInner).toHaveBeenCalledTimes(1);
    expect(closeOuter).not.toHaveBeenCalled();

    pressEscape();
    expect(closeOuter).toHaveBeenCalledTimes(1);
    expect(closeInner).toHaveBeenCalledTimes(1);
  });

  it('yields to an SGDS modal stacked above the layer', () => {
    const closeLayer = vi.fn();
    const closeModal = vi.fn();
    render(
      <>
        <Layer onEscape={closeLayer} zIndex={1055} />
        <ForeignModal onEscape={closeModal} zIndex={2000} />
      </>,
    );

    pressEscape();

    expect(closeModal).toHaveBeenCalledTimes(1);
    expect(closeLayer).not.toHaveBeenCalled();
  });

  it('closes the layer without also closing an SGDS modal below it', () => {
    const closeLayer = vi.fn();
    const closeModal = vi.fn();
    render(
      <>
        <ForeignModal onEscape={closeModal} zIndex={1055} />
        <Layer onEscape={closeLayer} zIndex={1060} />
      </>,
    );

    pressEscape();

    expect(closeLayer).toHaveBeenCalledTimes(1);
    expect(closeModal).not.toHaveBeenCalled();
  });

  it('keeps stack order when the layer re-renders with a new handler', () => {
    const closeOuter = vi.fn();
    const closeInner = vi.fn();
    function Rerendering() {
      const [, setTick] = useState(0);
      return (
        <>
          {/* A fresh closure every render must not push this layer back to the top. */}
          <Layer onEscape={() => closeOuter()} zIndex={1055} />
          <Layer onEscape={() => closeInner()} zIndex={1065} />
          <button onClick={() => setTick(t => t + 1)}>rerender</button>
        </>
      );
    }
    const { getByText } = render(<Rerendering />);
    fireEvent.click(getByText('rerender'));

    pressEscape();

    expect(closeInner).toHaveBeenCalledTimes(1);
    expect(closeOuter).not.toHaveBeenCalled();
  });

  it('does not let a high z-index nested inside a modal out-stack a modal opened later', () => {
    // The monitor dialog's fullscreen diagram: z-index 1080, but nested inside the dialog's own
    // 1055 stacking context, so a filter modal opened afterwards is still the topmost thing.
    const exitFullscreen = vi.fn();
    const closeFilterModal = vi.fn();
    function DialogWithFullscreen() {
      const ref = useRef<HTMLDivElement>(null);
      useEscapeLayer(exitFullscreen, { ref });
      return (
        <div className="modal show" style={{ position: 'fixed', zIndex: 1055 }}>
          <div ref={ref} style={{ position: 'fixed', zIndex: 1080 }} />
        </div>
      );
    }
    render(
      <>
        <DialogWithFullscreen />
        <ForeignModal onEscape={closeFilterModal} zIndex={1055} />
      </>,
    );

    pressEscape();

    expect(closeFilterModal).toHaveBeenCalledTimes(1);
    expect(exitFullscreen).not.toHaveBeenCalled();
  });

  it('picks the layer painting on top even when it registered first', () => {
    // The cluster side panel (z 1050) opened before the page went fullscreen (z 1040).
    const closePanel = vi.fn();
    const exitFullscreen = vi.fn();
    function LateFullscreen() {
      const [fullscreen, setFullscreen] = useState(false);
      return (
        <>
          <Layer onEscape={closePanel} zIndex={1050} />
          <button onClick={() => setFullscreen(true)}>fullscreen</button>
          {fullscreen && <Layer onEscape={exitFullscreen} zIndex={1040} />}
        </>
      );
    }
    const { getByText } = render(<LateFullscreen />);
    fireEvent.click(getByText('fullscreen'));

    pressEscape();

    expect(closePanel).toHaveBeenCalledTimes(1);
    expect(exitFullscreen).not.toHaveBeenCalled();
  });

  it('leaves an open info popover to close itself, sparing the modal under it', () => {
    const closeLayer = vi.fn();
    const closeModal = vi.fn();
    /** An OverlayTrigger popover: bootstrap markup plus rootClose's Escape-on-*keyup* dismissal. */
    function Popover({ onDismiss }: { onDismiss: () => void }) {
      useEffect(() => {
        const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onDismiss(); };
        document.addEventListener('keyup', handler);
        return () => document.removeEventListener('keyup', handler);
      }, [onDismiss]);
      return <div className="popover show" />;
    }
    const dismissPopover = vi.fn();
    render(
      <>
        <ForeignModal onEscape={closeModal} zIndex={1055} />
        <Layer onEscape={closeLayer} zIndex={1060} />
        <Popover onDismiss={dismissPopover} />
      </>,
    );

    pressEscape();

    expect(closeLayer).not.toHaveBeenCalled();
    expect(closeModal).not.toHaveBeenCalled();
    act(() => {
      document.dispatchEvent(new KeyboardEvent('keyup', { key: 'Escape', bubbles: true }));
    });
    expect(dismissPopover).toHaveBeenCalledTimes(1);
  });

  it('applies the popover rule on pages with no layer of their own', () => {
    const closeModal = vi.fn();
    function Root() {
      useEscapeLayerRoot();
      return (
        <>
          <ForeignModal onEscape={closeModal} zIndex={1055} />
          <div className="popover show" />
        </>
      );
    }
    render(<Root />);

    pressEscape();

    expect(closeModal).not.toHaveBeenCalled();
  });

  it('falls back to the nearest positioned ancestor for a layer with no z-index of its own', () => {
    const closeLayer = vi.fn();
    const closeModal = vi.fn();
    function InheritingLayer({ onEscape }: { onEscape: () => void }) {
      const ref: RefObject<HTMLDivElement | null> = useRef<HTMLDivElement>(null);
      useEscapeLayer(onEscape, { ref });
      return (
        <div style={{ position: 'fixed', zIndex: 1080 }}>
          <div ref={ref} data-testid="inheriting" />
        </div>
      );
    }
    render(
      <>
        <InheritingLayer onEscape={closeLayer} />
        <ForeignModal onEscape={closeModal} zIndex={1055} />
      </>,
    );

    pressEscape();

    expect(closeLayer).toHaveBeenCalledTimes(1);
    expect(closeModal).not.toHaveBeenCalled();
  });
});
