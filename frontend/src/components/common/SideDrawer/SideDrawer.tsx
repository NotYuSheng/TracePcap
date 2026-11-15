import type { ReactNode } from 'react';
import { Badge, Button, Modal } from '@govtechsg/sgds-react';
import './SideDrawer.css';

interface SideDrawerProps {
  show: boolean;
  onHide: () => void;
  title: ReactNode;
  /** id for the title, used as the dialog's aria-labelledby. */
  titleId: string;
  /** A count beside the title, e.g. active filters. Hidden when 0 or absent. */
  badge?: number;
  /** Extra class on the dialog, for content-specific styling. */
  className?: string;
  /** Where to portal the drawer; pass the fullscreen element so it shows in fullscreen. */
  container?: HTMLElement;
  footer?: ReactNode;
  children: ReactNode;
}

/**
 * A full-height sheet on the right edge: an SGDS Modal styled as a drawer, so Escape, the
 * backdrop and the × close it through `onHide` and it joins the modal stack like any Modal.
 */
export function SideDrawer({
  show,
  onHide,
  title,
  titleId,
  badge,
  className,
  container,
  footer,
  children,
}: SideDrawerProps) {
  return (
    <Modal
      show={show}
      onHide={onHide}
      dialogClassName={`side-drawer${className ? ` ${className}` : ''}`}
      contentClassName="side-drawer-content"
      aria-labelledby={titleId}
      container={container}
    >
      <Modal.Header closeButton>
        <Modal.Title id={titleId} as="h2" className="side-drawer-title">
          {title}
          {badge !== undefined && badge > 0 && (
            <Badge bg="primary" className="ms-2">
              {badge}
            </Badge>
          )}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="side-drawer-body">{children}</Modal.Body>
      {footer && <Modal.Footer className="side-drawer-footer">{footer}</Modal.Footer>}
    </Modal>
  );
}

/** The filter drawers' footer: Clear all, and a primary button that closes the drawer. */
export function FilterDrawerFooter({
  onClearAll,
  canClear,
  onDone,
  doneLabel,
}: {
  onClearAll: () => void;
  canClear: boolean;
  onDone: () => void;
  doneLabel: string;
}) {
  return (
    <>
      <Button variant="outline-secondary" onClick={onClearAll} disabled={!canClear}>
        Clear all
      </Button>
      <Button variant="primary" className="side-drawer-primary" onClick={onDone}>
        {doneLabel}
      </Button>
    </>
  );
}

/** The muted count after a filter chip's label; nothing while counts load or for a missing value. */
export function FilterPillCount({ n }: { n: number | undefined }) {
  if (n === undefined) return null;
  return <span className="filter-pill-count">{n.toLocaleString()}</span>;
}
