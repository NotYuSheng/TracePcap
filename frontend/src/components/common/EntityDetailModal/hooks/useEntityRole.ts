import { useEffect, useState } from 'react';
import { insightsService } from '@/features/insights/services/insightsService';
import type { NodeRole } from '@/features/insights/types/insights.types';
import type { EntityType } from '@/features/notes/services/entityNotesService';

/**
 * Node role state + actions for IP/DEVICE entities (load, AI suggest, accept,
 * discard, manual edit/save).
 */
export function useEntityRole(entityType: EntityType, entityKey: string, fileId: string, showRole: boolean) {
  const [role, setRole] = useState<NodeRole | null>(null);
  const [roleLoading, setRoleLoading] = useState(false);
  const [roleSuggesting, setRoleSuggesting] = useState(false);
  const [roleSuggestError, setRoleSuggestError] = useState<string | null>(null);
  const [roleInfoOpen, setRoleInfoOpen] = useState(false);
  const [roleEditing, setRoleEditing] = useState(false);
  const [roleLabelDraft, setRoleLabelDraft] = useState('');
  const [roleDescDraft, setRoleDescDraft] = useState('');
  const [roleSaving, setRoleSaving] = useState(false);

  // Load node role on mount for IP/DEVICE
  useEffect(() => {
    let active = true;
    // Reset so a previous entity's role/drafts can't leak when the modal is reused.
    setRole(null);
    setRoleLabelDraft('');
    setRoleDescDraft('');
    setRoleEditing(false);
    if (!showRole) return;
    setRoleLoading(true);
    insightsService
      .getNodeRole(entityType, entityKey)
      .then(r => { if (active) setRole(r); })
      .finally(() => { if (active) setRoleLoading(false); });
    return () => { active = false; };
  }, [showRole, entityType, entityKey]);

  const suggest = async () => {
    if (!fileId) return;
    setRoleSuggesting(true);
    setRoleSuggestError(null);
    try {
      const suggested = await insightsService.suggestNodeRole(entityType, entityKey, fileId);
      setRole(suggested);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Suggestion failed.';
      setRoleSuggestError(msg);
    } finally {
      setRoleSuggesting(false);
    }
  };

  const accept = async () => {
    if (!role) return;
    setRoleSaving(true);
    try {
      const updated = await insightsService.upsertNodeRole(
        entityType,
        entityKey,
        role.roleLabel ?? '',
        role.roleDescription ?? '',
        true,
      );
      setRole(updated);
    } finally {
      setRoleSaving(false);
    }
  };

  const discard = async () => {
    setRoleSaving(true);
    try {
      await insightsService.deleteNodeRole(entityType, entityKey);
      setRole(null);
    } finally {
      setRoleSaving(false);
    }
  };

  const openEdit = () => {
    setRoleLabelDraft(role?.roleLabel ?? '');
    setRoleDescDraft(role?.roleDescription ?? '');
    setRoleEditing(true);
  };

  const save = async () => {
    setRoleSaving(true);
    try {
      const updated = await insightsService.upsertNodeRole(
        entityType,
        entityKey,
        roleLabelDraft,
        roleDescDraft,
        true,
      );
      setRole(updated);
      setRoleEditing(false);
    } finally {
      setRoleSaving(false);
    }
  };

  return {
    role,
    roleLoading,
    roleSuggesting,
    roleSuggestError,
    roleInfoOpen,
    setRoleInfoOpen,
    roleEditing,
    setRoleEditing,
    roleLabelDraft,
    setRoleLabelDraft,
    roleDescDraft,
    setRoleDescDraft,
    roleSaving,
    suggest,
    accept,
    discard,
    openEdit,
    save,
  };
}
