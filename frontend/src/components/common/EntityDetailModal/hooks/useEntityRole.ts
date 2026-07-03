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
    // Reset all transient role state so nothing leaks when the modal is reused.
    setRole(null);
    setRoleLabelDraft('');
    setRoleDescDraft('');
    setRoleEditing(false);
    setRoleSuggesting(false);
    setRoleSuggestError(null);
    setRoleSaving(false);
    setRoleInfoOpen(false);
    if (!showRole || !fileId) { setRoleLoading(false); return; }
    setRoleLoading(true);
    insightsService
      .getNodeRole(entityType, entityKey, fileId)
      .then(r => { if (active) setRole(r); })
      .catch(err => { console.error('Failed to fetch node role:', err); })
      .finally(() => { if (active) setRoleLoading(false); });
    return () => { active = false; };
  }, [showRole, entityType, entityKey, fileId]);

  const suggest = async () => {
    if (!fileId) return;
    setRoleSuggesting(true);
    setRoleSuggestError(null);
    try {
      // A confirmed label is never silently overwritten — suggest into the editor for review.
      if (role?.confirmedByHuman) {
        const s = await insightsService.suggestNodeRolePreview(entityType, entityKey, fileId);
        setRoleLabelDraft(s.roleLabel ?? '');
        setRoleDescDraft(s.roleDescription ?? '');
        setRoleEditing(true);
      } else {
        const suggested = await insightsService.suggestNodeRole(entityType, entityKey, fileId);
        setRole(suggested);
      }
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
        fileId,
      );
      setRole(updated);
    } catch (err) {
      console.error('Failed to accept role:', err);
    } finally {
      setRoleSaving(false);
    }
  };

  const discard = async () => {
    setRoleSaving(true);
    try {
      await insightsService.deleteNodeRole(entityType, entityKey, fileId);
      setRole(null);
    } catch (err) {
      console.error('Failed to discard role:', err);
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
        fileId,
      );
      setRole(updated);
      setRoleEditing(false);
    } catch (err) {
      console.error('Failed to save role:', err);
    } finally {
      setRoleSaving(false);
    }
  };

  const dismissStaleness = async () => {
    if (!fileId) return;
    setRoleSaving(true);
    try {
      const updated = await insightsService.dismissNodeRoleStaleness(entityType, entityKey, fileId);
      setRole(updated);
    } catch (err) {
      console.error('Failed to dismiss label staleness:', err);
    } finally {
      setRoleSaving(false);
    }
  };

  /** Fetch a fresh AI suggestion from this snapshot's traffic and open the editor pre-filled. */
  const suggestUpdate = async () => {
    if (!fileId) return;
    setRoleSuggesting(true);
    setRoleSuggestError(null);
    try {
      const s = await insightsService.suggestNodeRolePreview(entityType, entityKey, fileId);
      setRoleLabelDraft(s.roleLabel ?? '');
      setRoleDescDraft(s.roleDescription ?? '');
      setRoleEditing(true);
    } catch (err: unknown) {
      setRoleSuggestError(err instanceof Error ? err.message : 'Suggestion failed.');
    } finally {
      setRoleSuggesting(false);
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
    dismissStaleness,
    suggestUpdate,
  };
}
