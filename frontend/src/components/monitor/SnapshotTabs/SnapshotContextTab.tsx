import { useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { insightsService } from '@/features/insights/services/insightsService';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

interface Props {
  networkId: string;
  snapshot: NetworkSnapshot;
  onSnapshotUpdated: (updated: NetworkSnapshot) => void;
}

/** What was happening during this capture, and analyst notes on it: both go to the AI for insights. */
export function SnapshotContextTab({ networkId, snapshot, onSnapshotUpdated }: Props) {
  const [contextDraft, setContextDraft] = useState(snapshot.context ?? '');
  const [notesDraft, setNotesDraft] = useState(snapshot.notes ?? '');
  const [savingContext, setSavingContext] = useState(false);
  const contextChanged = contextDraft !== (snapshot.context ?? '') || notesDraft !== (snapshot.notes ?? '');

  const handleSaveContext = async () => {
    setSavingContext(true);
    try {
      const updated = await insightsService.patchSnapshot(networkId, snapshot.id, {
        context: contextDraft,
        notes: notesDraft,
      });
      onSnapshotUpdated(updated);
    } finally {
      setSavingContext(false);
    }
  };

  return (
    <div>
      <p className="text-muted small mb-3">
        Provide context about this capture — what was happening at the time, what you were
        testing, or any operational notes. This is sent to the AI when generating insights
        for this snapshot.
      </p>
      <label className="form-label fw-semibold small">Context</label>
      <textarea
        className="form-control form-control-sm mb-3"
        rows={4}
        placeholder="e.g. Post-maintenance scan after PLC firmware update on 192.168.1.45. Expected MAC changes on floor 3."
        value={contextDraft}
        onChange={e => setContextDraft(e.target.value)}
      />
      <label className="form-label fw-semibold small">Notes</label>
      <textarea
        className="form-control form-control-sm mb-3"
        rows={3}
        placeholder="Any additional analyst notes…"
        value={notesDraft}
        onChange={e => setNotesDraft(e.target.value)}
      />
      <Button
        size="sm"
        variant="primary"
        onClick={handleSaveContext}
        disabled={savingContext || !contextChanged}
      >
        {savingContext
          ? <><Spinner animation="border" size="sm" className="me-1" />Saving…</>
          : <><i className="bi bi-floppy me-1" />Save</>
        }
      </Button>
    </div>
  );
}
