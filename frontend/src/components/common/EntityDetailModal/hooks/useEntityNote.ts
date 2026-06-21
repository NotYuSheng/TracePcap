import { useEffect, useState } from 'react';
import {
  entityNotesService,
  type EntityNote,
  type EntityType,
} from '@/features/notes/services/entityNotesService';

/**
 * Global per-entity note: load on mount, edit draft, save, delete.
 */
export function useEntityNote(entityType: EntityType, entityKey: string) {
  const [noteText, setNoteText] = useState('');
  const [savedNote, setSavedNote] = useState<EntityNote | null>(null);
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteDeleting, setNoteDeleting] = useState(false);

  useEffect(() => {
    let active = true;
    // Reset so a previous entity's note can't leak when the modal is reused.
    setSavedNote(null);
    setNoteText('');
    entityNotesService.getNote(entityType, entityKey).then(note => {
      if (active && note) { setSavedNote(note); setNoteText(note.note); }
    });
    return () => { active = false; };
  }, [entityType, entityKey]);

  const save = async () => {
    setNoteSaving(true);
    try {
      const updated = await entityNotesService.upsertNote(entityType, entityKey, noteText);
      setSavedNote(updated);
    } finally { setNoteSaving(false); }
  };

  const remove = async () => {
    setNoteDeleting(true);
    try {
      await entityNotesService.deleteNote(entityType, entityKey);
      setSavedNote(null);
      setNoteText('');
    } finally { setNoteDeleting(false); }
  };

  const noteChanged = noteText !== (savedNote?.note ?? '');

  return { noteText, setNoteText, savedNote, noteSaving, noteDeleting, noteChanged, save, remove };
}
