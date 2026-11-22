import { useId } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import { InfoPopover } from '@components/common/InfoPopover';
import { asSentence, usePermission } from '@/features/me/useMe';
import type { PermissionAction } from '@/features/me/meService';

interface PermissionLockProps {
  action: PermissionAction;
  /** Extra classes on the lock button, e.g. spacing. */
  className?: string;
}

/**
 * Beside a control the caller's roles don't allow (#915 roles, step 4): a lock button whose
 * popover says which permission it needs and why the caller hasn't got it. Renders nothing when
 * they may. Grey the control out with `usePermission(action).allowed`; this explains it.
 */
export function PermissionLock({ action, className }: PermissionLockProps) {
  const { allowed, reason, permission } = usePermission(action);
  const id = `perm-lock-${useId().replace(/:/g, '')}`;
  if (allowed) return null;
  const label = permission?.label ?? 'This needs a permission';
  return (
    <EscapableOverlayTrigger
      trigger="click"
      placement="bottom"
      overlay={
        <InfoPopover id={id} kind="Not allowed" title={label} docs="features/roles-and-permissions">
          {reason ? asSentence(reason) : "Your roles don't include this."}
        </InfoPopover>
      }
    >
      <Button
        type="button"
        size="sm"
        variant="link"
        className={`permission-lock text-muted p-0 ${className ?? 'ms-1'}`}
        aria-label={`Why can't I? ${label}`}
        data-testid={`permission-lock-${action}`}
      >
        <i className="bi bi-lock" aria-hidden="true" />
      </Button>
    </EscapableOverlayTrigger>
  );
}
