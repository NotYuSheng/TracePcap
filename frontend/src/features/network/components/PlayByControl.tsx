export type AxisMode = 'window' | 'packets';

/** The time axis's two ways of playing a capture, as a choice in either bar's settings. */
export function PlayByControl({ mode, onChange }: { mode: AxisMode; onChange: (m: AxisMode) => void }) {
  return (
    <div className="ts-setting">
      <span className="ts-setting-label" id="ts-playby-label">Play by</span>
      <div className="ts-segmented ts-segmented-2" role="group" aria-labelledby="ts-playby-label">
        <button type="button" aria-pressed={mode === 'window'} onClick={() => onChange('window')}>
          Time window
        </button>
        <button type="button" aria-pressed={mode === 'packets'} onClick={() => onChange('packets')}>
          Packet by packet
        </button>
      </div>
      <span className="ts-hint">
        {mode === 'window'
          ? 'A window slides along the capture; its conversations show.'
          : 'One moment at a time: each packet flies along its conversation.'}
      </span>
    </div>
  );
}
