import { forwardRef, type ComponentPropsWithoutRef, type CSSProperties } from 'react';
import { useAuth } from 'react-oidc-context';
import { Dropdown } from '@govtechsg/sgds-react';

const pillStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '8px',
  padding: '3px 12px 3px 3px',
  border: '1px solid var(--sgds-border-color, #d0d5dd)',
  borderRadius: '999px',
  background: 'transparent',
  cursor: 'pointer',
  font: 'inherit',
  lineHeight: 1,
};

const avatarStyle: CSSProperties = {
  width: '28px',
  height: '28px',
  borderRadius: '50%',
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'var(--sgds-primary, #5b21b6)',
  color: '#fff',
  fontWeight: 600,
  fontSize: '12px',
  flex: '0 0 auto',
};

const nameStyle: CSSProperties = {
  fontSize: '14px',
  fontWeight: 500,
  color: 'var(--sgds-body-color, #344054)',
  maxWidth: '11rem',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
};

const caretStyle: CSSProperties = { fontSize: '11px', color: 'var(--sgds-text-muted, #98a2b3)' };

interface PillToggleProps extends ComponentPropsWithoutRef<'button'> {
  name: string;
  initial: string;
}

/** Custom dropdown toggle: a rounded pill with the user's avatar initial, name, and a caret. */
const PillToggle = forwardRef<HTMLButtonElement, PillToggleProps>(
  ({ name, initial, ...props }, ref) => (
    <button ref={ref} type="button" style={pillStyle} {...props}>
      <span style={avatarStyle}>{initial}</span>
      <span style={nameStyle}>{name}</span>
      <i className="bi bi-chevron-down" style={caretStyle}></i>
    </button>
  )
);
PillToggle.displayName = 'PillToggle';

/**
 * Header profile control — an avatar + name pill whose menu holds the signed-in identity and the
 * logout action. Rendered only when auth is enabled (so `useAuth` always has a provider), and
 * hidden until a session exists. A leading vertical divider separates it from the app actions.
 */
export function AuthMenu() {
  const auth = useAuth();

  if (!auth.isAuthenticated) return null;

  const profile = auth.user?.profile;
  const name = profile?.preferred_username ?? profile?.email ?? profile?.name ?? 'Account';
  const initial = name.charAt(0).toUpperCase();

  return (
    <>
      <div className="vr mx-1 d-none d-lg-block" style={{ opacity: 0.2, alignSelf: 'stretch' }} />
      <Dropdown align="end">
        <Dropdown.Toggle as={PillToggle} name={name} initial={initial} id="user-menu" />
        <Dropdown.Menu>
          <Dropdown.Header>
            <div className="text-muted small">Signed in as</div>
            <div className="fw-semibold text-body text-truncate" style={{ maxWidth: '12rem' }}>
              {name}
            </div>
          </Dropdown.Header>
          <Dropdown.Divider />
          <Dropdown.Item onClick={() => void auth.signoutRedirect()}>
            <i className="bi bi-box-arrow-right me-2"></i>Logout
          </Dropdown.Item>
        </Dropdown.Menu>
      </Dropdown>
    </>
  );
}
