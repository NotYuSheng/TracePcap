import { isValidElement, useMemo, useState, type ComponentProps, type RefObject } from 'react';
import { OverlayTrigger } from '@govtechsg/sgds-react';
import { useEscapeLayer } from '@utils/useEscapeLayer';

type OverlayTriggerProps = ComponentProps<typeof OverlayTrigger>;

/**
 * A click-toggled `OverlayTrigger` (info/help popovers) that joins the shared Escape stack (#817).
 *
 * `rootClose` on its own does handle Escape, but through its own document listener. So a popover
 * opened inside an SGDS `Modal` closed together with the modal on a single Escape. CLAUDE.md
 * requires that Escape close exactly one layer, the topmost, and non-Modal popups must use
 * `useEscapeLayer` to get that. This keeps the popover open/closed state here, registers it as a
 * layer while it's open, and keeps `rootClose` for outside-click dismissal. Accepts the same props
 * as `OverlayTrigger`, so it is a drop-in replacement. `show`/`onToggle` are owned here.
 *
 * The layer is located through the overlay's `id`, read at Escape time, rather than through a ref.
 * OverlayTrigger attaches its own positioning ref to the overlay, and overriding that would break
 * placement. Every popover passed here should therefore have an `id`, which it needs for
 * aria-describedby anyway.
 */
export function EscapableOverlayTrigger({
  overlay,
  ...props
}: Omit<OverlayTriggerProps, 'show' | 'onToggle' | 'rootClose'>) {
  const [show, setShow] = useState(false);
  const overlayId =
    isValidElement<{ id?: string }>(overlay) && typeof overlay.props.id === 'string'
      ? overlay.props.id
      : undefined;
  const ref = useMemo(
    () =>
      ({
        get current() {
          return overlayId ? document.getElementById(overlayId) : null;
        },
      }) as RefObject<HTMLElement | null>,
    [overlayId]
  );

  useEscapeLayer(() => setShow(false), { enabled: show, ref });

  return <OverlayTrigger {...props} overlay={overlay} rootClose show={show} onToggle={setShow} />;
}
