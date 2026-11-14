import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import type { GroupNode } from '../services/networkGroups';
import type { NetworkMapEdits } from '../services/networkMapEdits';
import './NetworkMapGroupsModal.css';

interface Props {
  /** The map's groups as shown, with the analyst's edits applied. */
  tops: GroupNode[];
  edits: NetworkMapEdits;
  /** The group to open on (a box's name was clicked on the map). */
  focus?: string;
  canEdit: boolean;
  cannotEditReason?: string;
  onChange: (next: NetworkMapEdits) => void;
  onHide: () => void;
}

interface Row {
  group: GroupNode;
  depth: number;
  path: string;
  count: number;
}

function countOf(g: GroupNode): number {
  return g.nodeIds.length + g.children.reduce((n, c) => n + countOf(c), 0);
}

function flatten(tops: GroupNode[]): Row[] {
  const out: Row[] = [];
  const walk = (g: GroupNode, depth: number, path: string[]) => {
    const p = [...path, g.label];
    out.push({ group: g, depth, path: p.join(' › '), count: countOf(g) });
    g.children.forEach(c => walk(c, depth + 1, p));
  };
  tops.forEach(t => walk(t, 0, []));
  return out;
}

/** An id for a new group of the analyst's (crypto.randomUUID needs a secure context, which a LAN deployment may not be). */
function newGroupId(): string {
  return `user:${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * The network map's groups, as a list: add a group of your own inside any group that holds
 * groups, rename any group, give it a note, delete one of your own. The keyboard path to every
 * group edit; clicking a box's name on the map opens it on that group.
 */
export function NetworkMapGroupsModal({ tops, edits, focus, canEdit, cannotEditReason, onChange, onHide }: Props) {
  const rows = useMemo(() => flatten(tops), [tops]);
  const containers = rows.filter(r => r.group.children.length > 0);
  const [editing, setEditing] = useState<string | null>(focus ?? null);
  const [draftName, setDraftName] = useState('');
  const [draftNote, setDraftNote] = useState('');
  const [newName, setNewName] = useState('');
  const [newParent, setNewParent] = useState(containers.find(r => r.group.kind === 'network')?.group.id ?? containers[0]?.group.id ?? '');
  const focusRef = useRef<HTMLLIElement>(null);

  // Open the edit form of the group we came for, and bring it into view.
  useEffect(() => {
    if (!focus) return;
    const row = rows.find(r => r.group.id === focus);
    if (row) startEdit(row.group);
    requestAnimationFrame(() => focusRef.current?.scrollIntoView({ block: 'center' }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus]);

  function startEdit(g: GroupNode) {
    setEditing(g.id);
    setDraftName(g.label);
    setDraftNote(g.note ?? '');
  }

  const isUser = (id: string) => edits.groups.some(u => u.id === id);

  function save(g: GroupNode) {
    const name = draftName.trim();
    const note = draftNote.trim();
    const next: NetworkMapEdits = { ...edits, names: { ...edits.names }, notes: { ...edits.notes } };
    if (isUser(g.id)) {
      if (name) next.groups = edits.groups.map(u => (u.id === g.id ? { ...u, name } : u));
    } else {
      // An automatic group: a name of its own, or (cleared, or back to the automatic one) none.
      const automatic = g.autoLabel ?? g.label;
      if (!name || name === automatic) delete next.names[g.id];
      else next.names[g.id] = name;
    }
    if (note) next.notes[g.id] = note;
    else delete next.notes[g.id];
    onChange(next);
    setEditing(null);
  }

  function remove(id: string) {
    const placements = Object.fromEntries(Object.entries(edits.placements).filter(([, to]) => to !== id));
    const names = { ...edits.names };
    const notes = { ...edits.notes };
    delete names[id];
    delete notes[id];
    onChange({ ...edits, groups: edits.groups.filter(u => u.id !== id), placements, names, notes });
    if (editing === id) setEditing(null);
  }

  function add() {
    const name = newName.trim();
    if (!name || !newParent) return;
    onChange({ ...edits, groups: [...edits.groups, { id: newGroupId(), name, parentId: newParent }] });
    setNewName('');
  }

  return (
    <Modal show onHide={onHide} size="lg" scrollable aria-labelledby="nm-groups-title">
      <Modal.Header closeButton>
        <Modal.Title id="nm-groups-title">Network map groups</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {!canEdit && (
          <Alert variant="info" className="mb-3">
            {cannotEditReason ?? "You can't edit this network map."}
          </Alert>
        )}
        <p className="text-muted small mb-3">
          Rename a group or give it a note: both show on the map and in the draw.io download. Add a group of your own,
          then drag devices into it on the map.
        </p>

        <Form
          className="nm-add"
          onSubmit={e => {
            e.preventDefault();
            add();
          }}
        >
          <Form.Group controlId="nm-new-name" className="nm-add-name">
            <Form.Label>New group</Form.Label>
            <Form.Control
              value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder="e.g. Payments (PCI scope)"
              maxLength={120}
              disabled={!canEdit}
            />
          </Form.Group>
          <Form.Group controlId="nm-new-parent" className="nm-add-parent">
            <Form.Label>Inside</Form.Label>
            <Form.Select value={newParent} onChange={e => setNewParent(e.target.value)} disabled={!canEdit}>
              {containers.map(r => (
                <option key={r.group.id} value={r.group.id}>
                  {r.path}
                </option>
              ))}
            </Form.Select>
          </Form.Group>
          <Button type="submit" variant="primary" disabled={!canEdit || !newName.trim() || !newParent}>
            Add group
          </Button>
        </Form>

        <ul className="nm-tree" aria-label="Groups">
          {rows.map(r => {
            const g = r.group;
            const mine = isUser(g.id);
            const open = editing === g.id;
            return (
              <li
                key={g.id}
                ref={g.id === focus ? focusRef : undefined}
                className={`nm-row${open ? ' nm-row-open' : ''}`}
                style={{ paddingLeft: `${r.depth * 18 + 8}px` }}
              >
                {open ? (
                  <Form
                    className="nm-edit"
                    onSubmit={e => {
                      e.preventDefault();
                      save(g);
                    }}
                  >
                    <Form.Group controlId={`nm-name-${g.id}`}>
                      <Form.Label>Name</Form.Label>
                      <Form.Control value={draftName} onChange={e => setDraftName(e.target.value)} maxLength={120} autoFocus disabled={!canEdit} />
                      {g.autoLabel && <Form.Text>Automatic name: {g.autoLabel}. Clear the field to go back to it.</Form.Text>}
                    </Form.Group>
                    <Form.Group controlId={`nm-note-${g.id}`}>
                      <Form.Label>Note</Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={2}
                        value={draftNote}
                        onChange={e => setDraftNote(e.target.value)}
                        maxLength={2000}
                        placeholder="Owner, location, purpose…"
                        disabled={!canEdit}
                      />
                    </Form.Group>
                    <div className="nm-edit-actions">
                      <Button type="submit" variant="primary" size="sm" disabled={!canEdit}>
                        Save
                      </Button>
                      <Button type="button" variant="outline-secondary" size="sm" onClick={() => setEditing(null)}>
                        Cancel
                      </Button>
                    </div>
                  </Form>
                ) : (
                  <>
                    <div className="nm-row-main">
                      <span className="nm-row-name">
                        {g.label}
                        {mine && <span className="nm-badge">Your group</span>}
                      </span>
                      <span className="nm-row-meta">
                        {r.count} {r.count === 1 ? 'device' : 'devices'}
                        {g.autoLabel && ` · renamed from ${g.autoLabel}`}
                      </span>
                      {g.note && <span className="nm-row-note">{g.note}</span>}
                    </div>
                    <div className="nm-row-actions">
                      <Button variant="link" size="sm" onClick={() => startEdit(g)} disabled={!canEdit} aria-label={`Edit ${g.label}`}>
                        Edit
                      </Button>
                      {mine && (
                        <Button variant="link" size="sm" className="text-danger" onClick={() => remove(g.id)} disabled={!canEdit} aria-label={`Delete ${g.label}`}>
                          Delete
                        </Button>
                      )}
                    </div>
                  </>
                )}
              </li>
            );
          })}
        </ul>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
