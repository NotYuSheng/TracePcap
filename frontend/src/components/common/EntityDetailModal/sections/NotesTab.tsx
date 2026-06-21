import type { EntityNote } from '@/features/notes/services/entityNotesService';

interface NotesTabProps {
  entityLabel: string;
  displayName: string;
  noteText: string;
  setNoteText: (v: string) => void;
  savedNote: EntityNote | null;
  noteSaving: boolean;
  noteDeleting: boolean;
  noteChanged: boolean;
  onSave: () => void;
  onDelete: () => void;
}

/** Notes tab — global per-entity note editor. */
export function NotesTab({
  entityLabel,
  displayName,
  noteText,
  setNoteText,
  savedNote,
  noteSaving,
  noteDeleting,
  noteChanged,
  onSave,
  onDelete,
}: NotesTabProps) {
  return (
    <div>
      <p className="text-muted small mb-2">
        Notes are saved globally for this {entityLabel} and persist across all captures.
      </p>
      <textarea
        className="form-control mb-2"
        rows={6}
        style={{ fontSize: '0.875rem' }}
        placeholder={`Add notes about ${displayName}…`}
        value={noteText}
        onChange={e => setNoteText(e.target.value)}
      />
      {savedNote && (
        <p className="text-muted" style={{ fontSize: '0.7rem' }}>
          Last updated: {new Date(savedNote.updatedAt).toLocaleString('en-GB')}
        </p>
      )}
      <div className="d-flex gap-2">
        <button
          className="btn btn-primary btn-sm"
          onClick={onSave}
          disabled={noteSaving || !noteChanged}
        >
          {noteSaving ? (
            <><span className="spinner-border spinner-border-sm me-1" role="status" />Saving…</>
          ) : (
            <><i className="bi bi-floppy me-1" />Save Note</>
          )}
        </button>
        {savedNote && (
          <button
            className="btn btn-outline-danger btn-sm"
            onClick={onDelete}
            disabled={noteDeleting}
          >
            {noteDeleting
              ? <span className="spinner-border spinner-border-sm" role="status" />
              : <><i className="bi bi-trash me-1" />Delete</>
            }
          </button>
        )}
      </div>
    </div>
  );
}
