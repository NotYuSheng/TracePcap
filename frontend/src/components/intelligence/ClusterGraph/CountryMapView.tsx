import { useState, useMemo } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from 'react-simple-maps';
import type { ClusterGraphResponse, ClusterNode } from '@/features/intelligence/services/intelligenceService';
import { formatBytes } from '@/utils/formatters';
import worldTopojson from '@/assets/geo/world-110m.json';
import centroids from '@/assets/geo/country-centroids.json';

const CENTROID_MAP = centroids as unknown as Record<string, [number, number]>;

// ── Minimum distance nudge ────────────────────────────────────────────────────
// Countries that share very similar centroids get nudged so markers don't overlap.
const MIN_DIST = 8; // degrees

function nudgePositions(
  positions: Array<{ id: string; lon: number; lat: number }>
): Array<{ id: string; lon: number; lat: number }> {
  const result = positions.map(p => ({ ...p }));
  for (let i = 0; i < 20; i++) {
    let moved = false;
    for (let a = 0; a < result.length; a++) {
      for (let b = a + 1; b < result.length; b++) {
        const dx = result[b].lon - result[a].lon;
        const dy = result[b].lat - result[a].lat;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < MIN_DIST && dist > 0) {
          const push = (MIN_DIST - dist) / 2;
          const nx = (dx / dist) * push;
          const ny = (dy / dist) * push;
          result[a].lon -= nx;
          result[a].lat -= ny;
          result[b].lon += nx;
          result[b].lat += ny;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  return result;
}

// ── Color helpers (same as ClusterGraph) ─────────────────────────────────────
function trafficColor(ratio: number): string {
  const r = Math.round(208 - ratio * (208 - 21));
  const g = Math.round(228 - ratio * (228 - 101));
  const b = Math.round(247 - ratio * (247 - 192));
  return `rgb(${r},${g},${b})`;
}

type ColorMode = 'risk' | 'traffic';

// ── Main component ────────────────────────────────────────────────────────────

interface CountryMapViewProps {
  data: ClusterGraphResponse;
  colorMode: ColorMode;
  selectedClusterId: string | null;
  onSelectCluster: (cluster: ClusterNode | null) => void;
}

export function CountryMapView({
  data,
  colorMode,
  selectedClusterId,
  onSelectCluster,
}: CountryMapViewProps) {
  const [zoom, setZoom] = useState(1);

  const MAX_BYTES = Math.max(...data.clusters.map(c => c.totalBytes), 1);

  // Build positioned clusters (country clusters + "Internal" floating)
  const { positioned, internalCluster } = useMemo(() => {
    const geo: Array<{ id: string; lon: number; lat: number }> = [];
    let internal: ClusterNode | undefined;

    for (const c of data.clusters) {
      if (c.id === 'cluster:internal' || c.id === 'cluster:unknown') {
        if (!internal) internal = c; // show just one "off-map" node
        continue;
      }
      // Extract country code from cluster id "country:<CC>"
      const cc = c.id.startsWith('country:') ? c.id.slice(8) : null;
      const coord = cc ? CENTROID_MAP[cc] : null;
      if (coord) {
        geo.push({ id: c.id, lon: coord[1], lat: coord[0] });
      }
    }

    return { positioned: nudgePositions(geo), internalCluster: internal };
  }, [data.clusters]);

  const clusterById = new Map(data.clusters.map(c => [c.id, c]));

  function handleClick(clusterId: string) {
    const c = clusterById.get(clusterId);
    if (!c) return;
    onSelectCluster(selectedClusterId === clusterId ? null : c);
  }

  const MARKER_RADIUS = 7;

  function markerFill(cluster: ClusterNode): string {
    if (colorMode === 'traffic') {
      return trafficColor(cluster.totalBytes / MAX_BYTES);
    }
    return cluster.riskCount > 0 ? '#e74c3c' : '#1a73e8';
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      {/* Zoom controls */}
      <div
        style={{
          position: 'absolute',
          bottom: 12,
          left: 12,
          zIndex: 10,
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}
      >
        <button
          className="btn btn-sm btn-light border"
          style={{ width: 28, height: 28, padding: 0, lineHeight: 1 }}
          onClick={() => setZoom(z => Math.min(z * 1.5, 8))}
          title="Zoom in"
        >+</button>
        <button
          className="btn btn-sm btn-light border"
          style={{ width: 28, height: 28, padding: 0, lineHeight: 1 }}
          onClick={() => setZoom(z => Math.max(z / 1.5, 1))}
          title="Zoom out"
        >−</button>
        <button
          className="btn btn-sm btn-light border"
          style={{ width: 28, height: 28, padding: 0, fontSize: 10 }}
          onClick={() => setZoom(1)}
          title="Reset zoom"
        >⌂</button>
      </div>

      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 130 }}
        style={{ width: '100%', height: '100%', background: 'var(--tp-surface, #fff)' }}
      >
        <ZoomableGroup zoom={zoom} onMoveEnd={({ zoom: z }) => setZoom(z)}>
          {/* Map background */}
          <Geographies geography={worldTopojson}>
            {({ geographies }) =>
              geographies.map(geo => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  style={{
                    default: { fill: '#e9ecef', stroke: '#ced4da', strokeWidth: 0.3, outline: 'none' },
                    hover: { fill: '#dee2e6', outline: 'none' },
                    pressed: { fill: '#dee2e6', outline: 'none' },
                  }}
                />
              ))
            }
          </Geographies>

          {/* Cluster markers — geo-positioned */}
          {positioned.map(({ id, lon, lat }) => {
            const cluster = clusterById.get(id);
            if (!cluster) return null;
            const r = MARKER_RADIUS / zoom;
            const isSelected = selectedClusterId === id;
            const fill = markerFill(cluster);
            const textColor = cluster.totalBytes / MAX_BYTES > 0.55 && colorMode === 'traffic' ? '#fff' : '#212529';

            return (
              <Marker key={id} coordinates={[lon, lat]} onClick={() => handleClick(id)}>
                <circle
                  r={r}
                  fill={fill}
                  stroke={isSelected ? '#0d6efd' : cluster.riskCount > 0 && colorMode !== 'traffic' ? '#e74c3c' : '#6c757d'}
                  strokeWidth={(isSelected ? 2 : 1) / zoom}
                  style={{ cursor: 'pointer' }}
                />
                {cluster.riskCount > 0 && colorMode !== 'traffic' && (
                  <text
                    textAnchor="middle"
                    y={-r - 2 / zoom}
                    style={{ fontSize: 8 / zoom, fill: '#e74c3c', pointerEvents: 'none' }}
                  >▲</text>
                )}
                <text
                  textAnchor="middle"
                  y={r + 9 / zoom}
                  style={{
                    fontSize: 8 / zoom,
                    fill: textColor,
                    fontWeight: isSelected ? 700 : 400,
                    pointerEvents: 'none',
                    textShadow: '0 0 3px #fff',
                  }}
                >
                  {cluster.label.length > 18 ? cluster.label.slice(0, 16) + '…' : cluster.label}
                </text>
              </Marker>
            );
          })}
        </ZoomableGroup>
      </ComposableMap>

      {/* Internal / Unknown cluster — floating card in top-left */}
      {internalCluster && (
        <div
          style={{
            position: 'absolute',
            top: 10,
            left: 10,
            background: 'var(--tp-surface, #fff)',
            border: selectedClusterId === internalCluster.id ? '2px solid #0d6efd' : '1px dashed #adb5bd',
            borderRadius: 8,
            padding: '6px 10px',
            fontSize: 11,
            cursor: 'pointer',
            boxShadow: '0 2px 6px rgba(0,0,0,0.12)',
            zIndex: 5,
            maxWidth: 180,
          }}
          onClick={() => handleClick(internalCluster.id)}
        >
          <div style={{ fontWeight: 600, marginBottom: 2 }}>
            <i className="bi bi-shield-fill me-1 text-secondary" style={{ fontSize: 10 }} />
            {internalCluster.label}
          </div>
          <div className="text-muted" style={{ fontSize: 10 }}>
            {internalCluster.hostCount.toLocaleString()} hosts · {formatBytes(internalCluster.totalBytes)}
          </div>
        </div>
      )}

      {/* Legend */}
      <div
        style={{
          position: 'absolute',
          bottom: 12,
          right: 12,
          background: 'var(--tp-surface, #fff)',
          border: '1px solid var(--tp-border, #dee2e6)',
          borderRadius: 6,
          padding: '6px 10px',
          fontSize: 10,
          color: 'var(--tp-text-muted, #6c757d)',
          zIndex: 5,
        }}
      >
        {colorMode === 'traffic'
          ? <div>Dark blue = more traffic</div>
          : <div style={{ color: '#e74c3c' }}>● Red = has risk alerts</div>
        }
      </div>
    </div>
  );
}
