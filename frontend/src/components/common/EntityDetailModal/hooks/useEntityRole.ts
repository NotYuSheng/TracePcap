import { useEffect, useState } from 'react';
import { insightsService } from '@/features/insights/services/insightsService';
import { aiJobsService } from '@/features/aiJobs/aiJobsService';
import { useAiJob } from '@/features/aiJobs/useAiJob';
import type { AiJob } from '@/features/aiJobs/aiJobs.types';
import type { NodeRole } from '@/features/insights/types/insights.types';
import type { EntityType } from '@/features/notes/services/entityNotesService';

/**
 * Node role state + actions for IP/DEVICE entities (load, AI suggest, accept,
 * discard, manual edit/save).
 */
export function useEntityRole(entityType: EntityType, entityKey: string, fileId: string, showRole: boolean) {
  const [role, setRole] = useState<NodeRole | null>(null);
  const [roleLoading, setRoleLoading] = useState(false);
  const [roleStarting, setRoleStarting] = useState(false);
  const [roleSuggestError, setRoleSuggestError] = useState<string | null>(null);
  const [roleInfoOpen, setRoleInfoOpen] = useState(false);
  const [roleEditing, setRoleEditing] = useState(false);
  const [roleLabelDraft, setRoleLabelDraft] = useState('');
  const [roleDescDraft, setRoleDescDraft] = useState('');
  const [roleSaving, setRoleSaving] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const reload = () => setReloadKey(k => k + 1);

  // Load node role on mount for IP/DEVICE
  useEffect(() => {
    let active = true;
    // Reset all transient role state so nothing leaks when the modal is reused.
    setRole(null);
    setRoleLabelDraft('');
    setRoleDescDraft('');
    setRoleEditing(false);
    setRoleStarting(false);
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
  }, [showRole, entityType, entityKey, fileId, reloadKey]);

  // Suggestions run in the background (one job at a time for the model): closing the card doesn't
  // lose one, and reopening it picks up a suggestion still on its way.
  const jobKey = `${entityType}:${entityKey}`;
  const failed = (job: AiJob) => setRoleSuggestError(job.error?.message || 'Suggestion failed.');
  const saveJob = useAiJob<NodeRole>('ROLE_SUGGESTION', showRole ? fileId : null, {
    onDone: suggested => { if (suggested) setRole(suggested); },
    onFailed: failed,
  }, jobKey);
  const previewJob = useAiJob<{ roleLabel?: string; roleDescription?: string }>('ROLE_PREVIEW', showRole ? fileId : null, {
    onDone: s => {
      setRoleLabelDraft(s?.roleLabel ?? '');
      setRoleDescDraft(s?.roleDescription ?? '');
      setRoleEditing(true);
    },
    onFailed: failed,
  }, jobKey);
  const roleJob = saveJob.active ? saveJob.job : previewJob.active ? previewJob.job : null;
  const roleSuggesting = roleStarting || !!roleJob;

  const startSuggestion = async (preview: boolean) => {
    if (!fileId) return;
    setRoleStarting(true);
    setRoleSuggestError(null);
    try {
      const job = preview ? previewJob : saveJob;
      await job.start(() => aiJobsService.startRoleSuggestion(fileId, entityType, entityKey, preview));
    } catch (err: unknown) {
      setRoleSuggestError(err instanceof Error ? err.message : 'Suggestion failed.');
    } finally {
      setRoleStarting(false);
    }
  };

  // A confirmed label is never silently overwritten — suggest into the editor for review.
  const suggest = () => startSuggestion(!!role?.confirmedByHuman);

  const cancelSuggestion = () => (saveJob.active ? saveJob.cancel() : previewJob.cancel());

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

  // Removes the role outright — used both to discard an AI suggestion and to delete a
  // human-confirmed label (the backend delete re-fires downstream re-adjudication either way).
  const discard = async () => {
    setRoleSaving(true);
    try {
      await insightsService.deleteNodeRole(entityType, entityKey, fileId);
      setRole(null);
      setRoleEditing(false);
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
  const suggestUpdate = () => startSuggestion(true);

  return {
    role,
    roleLoading,
    roleSuggesting,
    roleJob,
    cancelSuggestion,
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
    reload,
  };
}
