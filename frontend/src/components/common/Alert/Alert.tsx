import { forwardRef } from 'react';
import type { ComponentProps } from 'react';
import { Alert as SgdsAlert } from '@govtechsg/sgds-react';

type SgdsAlertProps = ComponentProps<typeof SgdsAlert>;

/**
 * React 19 ignores `defaultProps` on function components, but SGDS's `Alert`
 * (a `forwardRef` component) relies on `defaultProps` for `show` and `transition`.
 * Without them `show` is `undefined`, so the SGDS Alert returns `null` and the
 * page shows an empty, invisible container instead of the alert.
 *
 * This drop-in wrapper restores the intended defaults so alerts always render.
 * The fade transition is disabled by default (react-transition-group's Fade also
 * misbehaves under React 19) — alerts appear immediately instead of fading in.
 * Callers can still override `show`/`transition` explicitly.
 */
const AlertBase = forwardRef<HTMLDivElement, SgdsAlertProps>(
  ({ show = true, transition = false, ...props }, ref) => (
    <SgdsAlert ref={ref} show={show} transition={transition} {...props} />
  )
);
AlertBase.displayName = 'Alert';

export const Alert = Object.assign(AlertBase, {
  Heading: SgdsAlert.Heading,
  Link: SgdsAlert.Link,
});
