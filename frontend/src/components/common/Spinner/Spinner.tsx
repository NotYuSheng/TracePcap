interface SpinnerProps {
  animation?: 'border' | 'grow';
  size?: 'sm';
  className?: string;
  style?: React.CSSProperties;
  role?: string;
}

export function Spinner({ animation = 'border', size, className, style, role }: SpinnerProps) {
  const sizeClass = size === 'sm' ? `spinner-${animation}-sm` : '';
  const cls = [`spinner-${animation}`, sizeClass, className].filter(Boolean).join(' ');
  return <div className={cls} style={style} role={role ?? 'status'} aria-hidden="true" />;
}
