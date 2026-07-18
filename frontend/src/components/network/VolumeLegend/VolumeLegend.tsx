import { formatBytes } from '@/utils/formatters';
import { volumeGradientCss } from '@/utils/volumeColor';
import './VolumeLegend.css';

interface VolumeLegendProps {
  /** Largest value on the current scale — the gradient's high end. */
  maxValue: number;
  /** Smallest positive value on the current scale — the gradient's low end. */
  minValue?: number;
  dark: boolean;
  /** Which ramp this legend describes. Must match the marks it explains. */
  variant?: 'cell' | 'edge';
  label?: string;
  className?: string;
}

/**
 * Gradient legend for the shared volume colour scale.
 *
 * Rendered next to both the heatmap and the volume-coloured diagram edges so the
 * two are visibly reading from the same scale. The `variant` must match the marks
 * being explained — the edge ramp is floored for visibility, so labelling edges
 * with a cell gradient would misstate the mapping.
 *
 * The scale is logarithmic, which is called out in the tooltip: without that note
 * a reader would reasonably assume the midpoint is half the maximum.
 */
export const VolumeLegend = ({
  maxValue,
  minValue = 1,
  dark,
  variant = 'cell',
  label = 'Volume',
  className = '',
}: VolumeLegendProps) => (
  <div
    className={`tp-volume-legend ${className}`}
    title={`${label}: logarithmic scale, ${formatBytes(minValue)} to ${formatBytes(maxValue)}`}
  >
    <span className="tp-volume-legend-label">{label}</span>
    {/* Labelled with the actual low end, not 0 — the ramp is fitted to the
        observed range, so claiming it starts at zero would misstate the mapping. */}
    <span className="tp-volume-legend-min">{formatBytes(minValue)}</span>
    <span
      className="tp-volume-legend-bar"
      style={{ backgroundImage: volumeGradientCss(maxValue, dark, variant, minValue) }}
      aria-hidden="true"
    />
    <span className="tp-volume-legend-max">{formatBytes(maxValue)}</span>
    <span className="tp-volume-legend-log" title="Shading is on a logarithmic scale">
      log
    </span>
  </div>
);
