import { Button, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
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
      <Form.Label htmlFor="entity-note-textarea" className="visually-hidden">
        Notes for {displayName}
      </Form.Label>
      <Form.Control
        as="textarea"
        id="entity-note-textarea"
        className="mb-2"
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
        <Button
          variant="primary"
          size="sm"
          onClick={onSave}
          disabled={noteSaving || noteDeleting || !noteChanged}
        >
          {noteSaving ? (
            <><Spinner size="sm" className="me-1" />Saving…</>
          ) : (
            <><i className="bi bi-floppy me-1" />Save Note</>
          )}
        </Button>
        {savedNote && (
          <Button
            variant="outline-danger"
            size="sm"
            onClick={onDelete}
            disabled={noteDeleting || noteSaving}
          >
            {noteDeleting
              ? <Spinner size="sm" />
              : <><i className="bi bi-trash me-1" />Delete</>
            }
          </Button>
        )}
      </div>
    </div>
  );
}
