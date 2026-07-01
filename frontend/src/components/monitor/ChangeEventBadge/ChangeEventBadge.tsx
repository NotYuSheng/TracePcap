import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';

interface ChangeEventBadgeProps {
  event: ChangeEvent;
  snapshots: NetworkSnapshot[];
  onPatch: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
}

const SEVERITY_CLASSES: Record<string, string> = {
  CRITICAL: 'text-danger',
  WARNING:  'text-warning',
  INFO:     'text-info',
};

const SEVERITY_ICONS: Record<string, string> = {
  CRITICAL: 'bi-exclamation-circle-fill',
  WARNING:  'bi-exclamation-triangle-fill',
  INFO:     'bi-info-circle-fill',
};

function describeEvent(event: ChangeEvent): string {
  const nv = event.newValue ?? {};
  const ov = event.oldValue ?? {};

  switch (event.changeType) {
    case 'MAC_ADDED': {
      const parts = [nv['manufacturer'], nv['deviceType']].filter(Boolean);
      const parens = parts.length ? ` (${parts.join(', ')})` : '';
      return `New device: ${event.entityKey}${parens}${nv['ip'] ? ` at ${nv['ip']}` : ''}`;
    }
    case 'IP_MAC_DRIFT':
      if (ov['mac'] && nv['mac'] && ov['mac'] !== nv['mac']) {
        // IP→MAC change: same IP, different MAC (possible ARP spoofing)
        return `Potential ARP spoof: ${event.entityKey} — MAC changed from ${ov['mac']} to ${nv['mac']}`;
      }
      // MAC→IP change: same MAC, different IP (DHCP reassignment)
      return `IP reassignment: ${event.entityKey} — IP changed from ${ov['ip'] ?? '?'} to ${nv['ip'] ?? '?'}`;
    case 'ASN_CHANGE':
      return `New ISP/ASN seen: ${nv['asn']}${nv['org'] ? ` — ${nv['org']}` : ''}${nv['country'] ? ` (${nv['country']})` : ''}`;
    case 'GATEWAY_CHANGE': {
      const fmtGw = (ip: unknown, org: unknown) => `${ip ?? '?'}${org ? ` (${org})` : ''}`;
      return `Gateway changed: ${fmtGw(ov['ip'], ov['org'])} → ${fmtGw(nv['ip'], nv['org'])}`;
    }
    case 'APP_ADDED':
      return `New application: ${event.entityKey}`;
    case 'PROTOCOL_ADDED':
      return `New protocol: ${event.entityKey}`;
    case 'VPN_DRIFT':
      if (nv['riskType']) return `VPN detected: ${nv['riskType']}`;
      return `VPN signal gone: ${ov['riskType'] ?? event.entityKey}`;
    case 'LABEL_STALE': {
      const changes = Array.isArray(nv['changes']) ? (nv['changes'] as string[]).join(', ') : '';
      const label = nv['roleLabel'] ? ` (${nv['roleLabel']})` : '';
      return `Label may be stale: ${event.entityKey}${label}${changes ? ` — ${changes}` : ''}`;
    }
    default:
      return event.entityKey;
  }
}

export const ChangeEventBadge = ({ event, snapshots, onPatch }: ChangeEventBadgeProps) => {
  const toSnap = snapshots.find(s => s.id === event.toSnapshotId);
  const detectedMs = parseDateTime(event.detectedAt as unknown as string | number[]);
  const formattedTime = new Date(detectedMs).toLocaleString('en-GB');

  const [showNotes, setShowNotes] = useState(false);
  const [draftNotes, setDraftNotes] = useState(event.notes ?? '');
  const [saving, setSaving] = useState(false);
  // Optimistic local state so UI responds immediately
  const [localReviewed, setLocalReviewed] = useState(event.reviewed);
  const [localNotes, setLocalNotes] = useState(event.notes ?? '');

  // Keep local state in sync when the parent refreshes the event from the server
  useEffect(() => { setLocalReviewed(event.reviewed); }, [event.reviewed]);
  useEffect(() => { setLocalNotes(event.notes ?? ''); }, [event.notes]);

  const handleReviewToggle = async () => {
    const next = !localReviewed;
    setLocalReviewed(next);
    setSaving(true);
    try {
      await onPatch(event.id, { reviewed: next });
    } catch {
      setLocalReviewed(!next); // revert on error
    } finally {
      setSaving(false);
    }
  };

  const handleSaveNotes = async () => {
    setSaving(true);
    try {
      await onPatch(event.id, { notes: draftNotes.trim() || null });
      setLocalNotes(draftNotes.trim());
      setShowNotes(false);
    } catch {
      // revert draft to last saved
      setDraftNotes(localNotes);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className={`d-flex align-items-start gap-3 py-2 border-bottom${localReviewed ? ' opacity-50' : ''}`}
      style={{ transition: 'opacity 0.2s' }}
    >
      <i
        className={`bi ${SEVERITY_ICONS[event.severity] ?? 'bi-circle-fill'} ${SEVERITY_CLASSES[event.severity] ?? ''} flex-shrink-0 mt-1`}
      />
      <div className="flex-grow-1 min-w-0">
        <div className="text-break">{describeEvent(event)}</div>
        {toSnap && (
          <small className="text-muted d-block">
            Snapshot {toSnap.snapshotOrder + 1}: {toSnap.fileName}
          </small>
        )}
        {localNotes && !showNotes && (
          <small className="text-muted fst-italic d-block mt-1">
            <i className="bi bi-chat-left-text me-1"></i>{localNotes}
          </small>
        )}
        {showNotes && (
          <div className="mt-2">
            <Form.Control
              as="textarea"
              size="sm"
              rows={2}
              placeholder="Add notes…"
              value={draftNotes}
              onChange={e => setDraftNotes(e.target.value)}
              autoFocus
            />
            <div className="d-flex gap-1 mt-1">
              <Button
                size="sm"
                variant="primary"
                onClick={handleSaveNotes}
                disabled={saving}
              >
                {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
                Save
              </Button>
              <Button
                size="sm"
                variant="outline-secondary"
                onClick={() => { setShowNotes(false); setDraftNotes(localNotes); }}
                disabled={saving}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
      </div>

      <div className="d-flex align-items-center gap-2 flex-shrink-0">
        <small className="text-muted text-nowrap">{formattedTime}</small>
        <Button
          size="sm"
          variant="link"
          className="p-0 text-muted"
          title={showNotes ? 'Hide notes' : (localNotes ? 'Edit notes' : 'Add notes')}
          onClick={() => { setShowNotes(v => !v); setDraftNotes(localNotes); }}
        >
          <i className={`bi bi-chat-left-text${localNotes ? '-fill' : ''}`}></i>
        </Button>
        <Button
          size="sm"
          variant="link"
          className={`p-0 ${localReviewed ? 'text-success' : 'text-muted'}`}
          title={localReviewed ? 'Mark as unreviewed' : 'Mark as reviewed'}
          onClick={handleReviewToggle}
          disabled={saving}
        >
          <i className={`bi bi-check-circle${localReviewed ? '-fill' : ''}`}></i>
        </Button>
      </div>
    </div>
  );
};
