import { useEffect, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { useStore } from '@/store';
import {
  NODE_LABEL_FIELD_META,
  type NodeLabelConfig,
  type NodeLabelFieldOption,
} from '@/store/slices/nodeLabelSlice';

interface NodeLabelSettingsModalProps {
  show: boolean;
  onHide: () => void;
  /** Render target so the modal stays inside the (possibly fullscreen) graph card. */
  container?: HTMLElement;
}

/** Example values used to render a live preview of the chosen label layout. */
const PREVIEW_VALUES: Record<string, string> = {
  ip: '192.168.1.42',
  hostname: 'Johns-MacBook.local',
  mac: 'a4:83:e7:1a:2b:3c',
  deviceType: 'Laptop / Desktop',
  manufacturer: 'Apple',
};

/**
 * Lets the analyst choose which host attributes (and optional custom text) are drawn
 * as lines of text beneath each node in the network topology graph.
 */
export const NodeLabelSettingsModal = ({ show, onHide, container }: NodeLabelSettingsModalProps) => {
  const config = useStore(s => s.nodeLabelConfig);
  const setNodeLabelConfig = useStore(s => s.setNodeLabelConfig);
  const resetNodeLabelConfig = useStore(s => s.resetNodeLabelConfig);

  // Draft state so changes only apply on Save.
  const [fields, setFields] = useState<NodeLabelFieldOption[]>(config.fields);
  const [customText, setCustomText] = useState(config.customText);

  // Re-seed the draft from the live config each time the modal opens.
  useEffect(() => {
    if (show) {
      setFields(config.fields);
      setCustomText(config.customText);
    }
  }, [show, config]);

  const toggleField = (index: number) =>
    setFields(prev => prev.map((f, i) => (i === index ? { ...f, enabled: !f.enabled } : f)));

  const moveField = (index: number, dir: -1 | 1) =>
    setFields(prev => {
      const target = index + dir;
      if (target < 0 || target >= prev.length) return prev;
      const next = [...prev];
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });

  const handleSave = () => {
    const newConfig: NodeLabelConfig = { fields, customText };
    setNodeLabelConfig(newConfig);
    onHide();
  };

  const handleReset = () => {
    resetNodeLabelConfig();
    onHide();
  };

  const previewLines = [
    ...fields.filter(f => f.enabled).map(f => PREVIEW_VALUES[f.field]),
    ...(customText.trim() ? [customText.trim()] : []),
  ];

  return (
    <Modal show={show} onHide={onHide} centered container={container}>
      <Modal.Header closeButton>
        <Modal.Title>Customize node labels</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted small mb-3">
          Choose which details appear as text beneath each node, and the order they stack in. Fields
          with no value for a given host are skipped automatically.
        </p>

        <div className="d-flex flex-column gap-1 mb-3">
          {fields.map((f, i) => (
            <div
              key={f.field}
              className="d-flex align-items-center gap-2 border rounded px-2 py-1"
            >
              <Form.Check
                type="checkbox"
                id={`node-label-${f.field}`}
                checked={f.enabled}
                onChange={() => toggleField(i)}
              />
              <i className={`bi ${NODE_LABEL_FIELD_META[f.field].icon} text-muted`} />
              <span className="flex-grow-1">{NODE_LABEL_FIELD_META[f.field].label}</span>
              <Button
                variant="outline-secondary"
                size="sm"
                className="py-0 px-1"
                title="Move up"
                disabled={i === 0}
                onClick={() => moveField(i, -1)}
              >
                <i className="bi bi-arrow-up" />
              </Button>
              <Button
                variant="outline-secondary"
                size="sm"
                className="py-0 px-1"
                title="Move down"
                disabled={i === fields.length - 1}
                onClick={() => moveField(i, 1)}
              >
                <i className="bi bi-arrow-down" />
              </Button>
            </div>
          ))}
        </div>

        <Form.Group className="mb-3">
          <Form.Label className="small fw-semibold mb-1">Custom text (optional)</Form.Label>
          <Form.Control
            type="text"
            placeholder="e.g. Lab segment"
            value={customText}
            maxLength={40}
            onChange={e => setCustomText(e.target.value)}
          />
          <Form.Text className="text-muted">
            Shown as the last line under every node.
          </Form.Text>
        </Form.Group>

        <div
          className="border rounded p-3 text-center"
          style={{ background: 'var(--tp-bg-subtle)', color: 'var(--tp-text)' }}
        >
          <div className="text-muted small mb-2">Preview</div>
          <i className="bi bi-pc-display-horizontal" style={{ fontSize: 24 }} />
          {previewLines.length > 0 ? (
            previewLines.map((line, i) => (
              <div key={i} style={{ fontSize: 11, fontWeight: 500, lineHeight: '13px' }}>
                {line}
              </div>
            ))
          ) : (
            <div className="text-muted fst-italic" style={{ fontSize: 11 }}>
              No fields selected — IP address will be shown as a fallback.
            </div>
          )}
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" className="me-auto" onClick={handleReset}>
          Reset to default
        </Button>
        <Button variant="secondary" onClick={onHide}>
          Cancel
        </Button>
        <Button variant="primary" onClick={handleSave}>
          Apply
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
