import { forwardRef, type ComponentProps, type ReactNode } from 'react';
import { Popover } from '@govtechsg/sgds-react';
import { docsUrl } from '@/config/docs';
import './InfoPopover.css';

type PopoverProps = ComponentProps<typeof Popover>;

export interface InfoPopoverProps extends Omit<PopoverProps, 'title' | 'children'> {
  /** Required: EscapableOverlayTrigger finds the layer by it. */
  id: string;
  /** A small label above the title saying what kind of note it is, e.g. "How it works". */
  kind?: string;
  title?: ReactNode;
  /** Where the numbers come from, in the footer: "Source: tshark". */
  source?: ReactNode;
  /** A docs page for the footer's "In the docs →" link, e.g. "features/story-mode". */
  docs?: string;
  /** Its anchor on that page. */
  docsAnchor?: string;
  /** Widest it may get, in px (default 330). */
  width?: number;
  children: ReactNode;
}

/**
 * The app's info popover (canvas "Info popovers", option B): a kind label, a title, the note, and
 * a footer with its source and a docs link. Pass it as an EscapableOverlayTrigger's overlay; it
 * forwards the trigger's positioning props to SGDS's Popover underneath.
 */
export const InfoPopover = forwardRef<HTMLDivElement, InfoPopoverProps>(function InfoPopover(
  { id, kind, title, source, docs, docsAnchor, width = 330, className, style, children, ...rest },
  ref
) {
  const link = docs ? docsUrl(docs, docsAnchor) : null;
  return (
    <Popover
      ref={ref}
      id={id}
      className={`info-popover${className ? ` ${className}` : ''}`}
      style={{ maxWidth: width, ...style }}
      {...rest}
    >
      <Popover.Body>
        {kind && <div className="info-popover-kind">{kind}</div>}
        {title && <div className="info-popover-title">{title}</div>}
        <div className="info-popover-text">{children}</div>
      </Popover.Body>
      {(source || link) && (
        <div className="info-popover-foot">
          {source ? <span>Source: {source}</span> : <span />}
          {link && (
            <a href={link} target="_blank" rel="noreferrer">
              In the docs
            </a>
          )}
        </div>
      )}
    </Popover>
  );
});
