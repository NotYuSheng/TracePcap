interface SpinnerProps {
  animation?: 'border' | 'grow';
  size?: 'sm';
  className?: string;
  style?: React.CSSProperties;
  role?: string;
  /** Announced to assistive technology; the spinner graphic itself is decorative. */
  label?: string;
}

export function Spinner({ animation = 'border', size, className, style, role, label }: SpinnerProps) {
  const sizeClass = size === 'sm' ? `spinner-${animation}-sm` : '';
  const cls = [`spinner-${animation}`, sizeClass, className].filter(Boolean).join(' ');
  // The spinner previously set role="status" *and* aria-hidden="true", so it announced nothing —
  // the role was unreachable and a screen reader got no indication anything was loading (#723).
  // The graphic itself is decorative, so it stays hidden; the status lives in a visually-hidden
  // label beside it, which is what actually reaches assistive technology.
  return (
    <span role={role ?? 'status'}>
      <span className={cls} style={style} aria-hidden="true" />
      <span className="visually-hidden">{label ?? 'Loading…'}</span>
    </span>
  );
}
