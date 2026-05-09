import { useState, useMemo, useEffect } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from 'react-simple-maps';
import type { ClusterGraphResponse, ClusterNode } from '@/features/intelligence/services/intelligenceService';
import { intelligenceService } from '@/features/intelligence/services/intelligenceService';
import { formatBytes } from '@/utils/formatters';
import worldTopojson from '@/assets/geo/world-50m.json';
import centroids from '@/assets/geo/country-centroids.json';

const CENTROID_MAP = centroids as unknown as Record<string, [number, number]>;

// ── Color helpers ──────────────────────────────────────────────────────────────
function trafficColor(ratio: number): string {
  const r = Math.round(208 - ratio * (208 - 21));
  const g = Math.round(228 - ratio * (228 - 101));
  const b = Math.round(247 - ratio * (247 - 192));
  return `rgb(${r},${g},${b})`;
}

type ColorMode = 'risk' | 'traffic';

// ── Zoom levels tuned per country size ────────────────────────────────────────
// zoom = (viewport_px * 0.7 / country_width_deg) / (scale * 2π / 360)
// With scale=160 base: divisor = 160 * 2π / 360 ≈ 2.79 px/deg per zoom unit
// SG 0.5°wide → zoom ≈ (1200*0.7/0.5)/2.79 ≈ 600
const COUNTRY_ZOOM: Record<string, number> = {
  SG: 600, MC: 1200, VA: 1200, LI: 800, SM: 800,
  MT: 400, BH: 200, QA: 150, KW: 150, BN: 150,
  MV: 150, BB: 300, GD: 300, LC: 300, VC: 300, DM: 300, AG: 300, KN: 300, TT: 200, JM: 200, MU: 300, SC: 200,
  LU: 300, AD: 500, CY: 100, LT: 80, LV: 80, EE: 80,
  GB: 40, DE: 40, FR: 30, JP: 30, KR: 60, IT: 30, ES: 25, TH: 25, MY: 30, PH: 25, VN: 35, MM: 25,
  SE: 20, NO: 15, FI: 20, PL: 35, UA: 15, TR: 20,
  CN: 14, US: 8, RU: 4, CA: 5, BR: 10, AU: 8, IN: 18, AR: 10, KZ: 8, MX: 12,
};

function countryView(cc: string): [number, number, number] {
  const c = CENTROID_MAP[cc];
  if (!c) return [0, 20, 2];
  return [c[1], c[0], COUNTRY_ZOOM[cc] ?? 10];
}

// ── Props ─────────────────────────────────────────────────────────────────────
interface CountryMapViewProps {
  data: ClusterGraphResponse;
  colorMode: ColorMode;
  selectedClusterId: string | null;
  onSelectCluster: (cluster: ClusterNode | null) => void;
  fileId: string;
}

export function CountryMapView({
  data,
  colorMode,
  selectedClusterId,
  onSelectCluster,
  fileId,
}: CountryMapViewProps) {
  const [drilledCountryId, setDrilledCountryId] = useState<string | null>(null);
  const [cityData, setCityData] = useState<ClusterGraphResponse | null>(null);
  const [cityLoading, setCityLoading] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [center, setCenter] = useState<[number, number]>([0, 20]);

  const MAX_BYTES = useMemo(() => Math.max(...data.clusters.map(c => c.totalBytes), 1), [data.clusters]);
  const clusterById = useMemo(() => new Map(data.clusters.map(c => [c.id, c])), [data.clusters]);
  const drilledCC = drilledCountryId?.startsWith('country:') ? drilledCountryId.slice(8) : null;
  const isDrilled = drilledCountryId !== null;

  const { internalCluster, unknownCluster } = useMemo(() => {
    let internal: ClusterNode | undefined;
    let unknown: ClusterNode | undefined;
    for (const c of data.clusters) {
      if (c.id === 'cluster:internal') internal = c;
      if (c.id === 'cluster:unknown') unknown = c;
    }
    return { internalCluster: internal, unknownCluster: unknown };
  }, [data.clusters]);

  // ── Fetch city data on drill-down ─────────────────────────────────────────
  useEffect(() => {
    if (!drilledCC) { setCityData(null); return; }
    setCityLoading(true);
    intelligenceService.getClusters(fileId, 'city')
      .then(d => setCityData(d))
      .catch(() => setCityData(null))
      .finally(() => setCityLoading(false));
  }, [drilledCC, fileId]);

  const cityClusters = useMemo(() => {
    if (!cityData || !drilledCC) return [];
    return cityData.clusters.filter(
      c => c.id.startsWith(`city:${drilledCC}:`) && c.lat != null && c.lon != null
    );
  }, [cityData, drilledCC]);

  const cityMaxBytes = Math.max(...cityClusters.map(c => c.totalBytes), 1);

  function drillInto(cc: string) {
    const clusterId = `country:${cc}`;
    if (!clusterById.has(clusterId)) return;
    const [cLon, cLat, cZoom] = countryView(cc);
    setCenter([cLon, cLat]);
    setZoom(cZoom);
    setDrilledCountryId(clusterId);
    onSelectCluster(null);
  }

  function exitDrillDown() {
    setDrilledCountryId(null);
    setCityData(null);
    setZoom(1);
    setCenter([0, 20]);
    onSelectCluster(null);
  }

  // ── Fill colours ──────────────────────────────────────────────────────────
  function countryFill(isoNumeric: string, hovered = false): string {
    const cc = isoNumericToAlpha2[isoNumeric];
    const cluster = cc ? clusterById.get(`country:${cc}`) : undefined;
    if (!cluster) return hovered ? '#dee2e6' : '#e9ecef';
    if (cc === drilledCC) return '#bbd4f7';
    const base = colorMode === 'traffic'
      ? trafficColor(cluster.totalBytes / MAX_BYTES)
      : cluster.riskCount > 0 ? '#fce8e6' : '#d6e4f7';
    return hovered ? base : base;
  }

  function markerFill(cluster: ClusterNode, maxBytes: number): string {
    if (colorMode === 'traffic') return trafficColor(cluster.totalBytes / maxBytes);
    return cluster.riskCount > 0 ? '#e74c3c' : '#1a73e8';
  }

  const noCityData = isDrilled && !cityLoading && cityData !== null && cityClusters.length === 0;

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>

      {/* Breadcrumb */}
      {isDrilled && (
        <div style={{ position: 'absolute', top: 10, left: 10, zIndex: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
          <button
            className="btn btn-sm btn-light border d-flex align-items-center gap-1"
            style={{ fontSize: 12 }}
            onClick={exitDrillDown}
          >
            <i className="bi bi-arrow-left" />
            World
          </button>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--tp-text, #212529)' }}>
            <i className="bi bi-geo-alt me-1" />
            {clusterById.get(drilledCountryId!)?.label ?? drilledCC}
          </span>
          {cityLoading && <span className="spinner-border spinner-border-sm text-primary" style={{ width: 14, height: 14, borderWidth: 2 }} />}
          {noCityData && <span className="text-muted" style={{ fontSize: 11 }}>No city-level data available</span>}
        </div>
      )}

      {/* Zoom controls */}
      <div style={{ position: 'absolute', bottom: 12, left: 12, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 4 }}>
        <button className="btn btn-sm btn-light border" style={{ width: 28, height: 28, padding: 0, lineHeight: 1 }}
          onClick={() => setZoom(z => Math.min(z * 1.5, 1200))} title="Zoom in">+</button>
        <button className="btn btn-sm btn-light border" style={{ width: 28, height: 28, padding: 0, lineHeight: 1 }}
          onClick={() => setZoom(z => Math.max(z / 1.5, 1))} title="Zoom out">−</button>
        <button className="btn btn-sm btn-light border" style={{ width: 28, height: 28, padding: 0, fontSize: 10 }}
          onClick={exitDrillDown} title="Reset view">⌂</button>
      </div>

      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 160 }}
        style={{ width: '100%', height: '100%', background: '#d6e8f5' }}
      >
        <ZoomableGroup
          zoom={zoom}
          center={center}
          maxZoom={1200}
          onMoveEnd={({ zoom: z, coordinates }) => {
            setZoom(z);
            setCenter(coordinates as [number, number]);
          }}
        >
          <Geographies geography={worldTopojson}>
            {({ geographies }) =>
              geographies.map(geo => {
                const isoNum = String(geo.id ?? geo.properties?.['iso_n3'] ?? '');
                const cc = isoNumericToAlpha2[isoNum];
                const hasCluster = !!cc && clusterById.has(`country:${cc}`);
                const clickable = !isDrilled && hasCluster;
                const fill = countryFill(isoNum);
                const hoverFill = hasCluster ? '#a8c8f0' : '#dee2e6';

                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    onClick={() => clickable && drillInto(cc!)}
                    style={{
                      default: {
                        fill,
                        stroke: '#b0bec5',
                        strokeWidth: 0.3 / zoom,
                        outline: 'none',
                        cursor: clickable ? 'pointer' : 'default',
                      },
                      hover: {
                        fill: hoverFill,
                        stroke: clickable ? '#0d6efd' : '#b0bec5',
                        strokeWidth: (clickable ? 0.8 : 0.3) / zoom,
                        outline: 'none',
                        cursor: clickable ? 'pointer' : 'default',
                      },
                      pressed: { fill, outline: 'none' },
                    }}
                  />
                );
              })
            }
          </Geographies>

          {/* Country labels on world view */}
          {!isDrilled && data.clusters
            .filter(c => c.id.startsWith('country:') && c.lat != null && c.lon != null)
            .map(cluster => {
              const labelText = cluster.label.replace(/ \([A-Z]{2}\)$/, '');
              return (
                <Marker key={`lbl-${cluster.id}`} coordinates={[cluster.lon!, cluster.lat!]}>
                  <text
                    textAnchor="middle"
                    style={{
                      fontSize: 8 / zoom,
                      fill: '#212529',
                      pointerEvents: 'none',
                      paintOrder: 'stroke',
                      stroke: '#fff',
                      strokeWidth: 3 / zoom,
                      strokeLinejoin: 'round',
                      fontWeight: 600,
                    }}
                  >
                    {labelText}
                  </text>
                </Marker>
              );
            })
          }

          {/* City markers when drilled */}
          {isDrilled && cityClusters.map(cluster => {
            const r = 6 / zoom;
            const isSelected = selectedClusterId === cluster.id;
            const fill = markerFill(cluster, cityMaxBytes);
            return (
              <Marker key={cluster.id} coordinates={[cluster.lon!, cluster.lat!]}
                onClick={() => onSelectCluster(isSelected ? null : cluster)}
              >
                <circle r={r} fill={fill}
                  stroke={isSelected ? '#0d6efd' : '#fff'}
                  strokeWidth={(isSelected ? 2 : 1) / zoom}
                  style={{ cursor: 'pointer' }}
                />
                {cluster.riskCount > 0 && colorMode !== 'traffic' && (
                  <text textAnchor="middle" y={-r - 2 / zoom}
                    style={{ fontSize: 8 / zoom, fill: '#e74c3c', pointerEvents: 'none' }}>▲</text>
                )}
                <text textAnchor="middle" y={r + 9 / zoom}
                  style={{
                    fontSize: 9 / zoom, fill: '#212529',
                    fontWeight: isSelected ? 700 : 400,
                    pointerEvents: 'none', paintOrder: 'stroke',
                    stroke: '#fff', strokeWidth: 3 / zoom, strokeLinejoin: 'round',
                  }}
                >
                  {cluster.label.split(',')[0]}
                </text>
              </Marker>
            );
          })}
        </ZoomableGroup>
      </ComposableMap>

      {/* Internal / Unknown cards */}
      {!isDrilled && (internalCluster || unknownCluster) && (
        <div style={{ position: 'absolute', top: 10, left: 10, display: 'flex', flexDirection: 'column', gap: 6, zIndex: 5 }}>
          {[internalCluster, unknownCluster].filter(Boolean).map(c => c && (
            <div key={c.id}
              style={{
                background: 'var(--tp-surface, #fff)',
                border: selectedClusterId === c.id ? '2px solid #0d6efd' : '1px dashed #adb5bd',
                borderRadius: 8, padding: '6px 10px', fontSize: 11,
                cursor: 'pointer', boxShadow: '0 2px 6px rgba(0,0,0,0.12)', maxWidth: 180,
              }}
              onClick={() => onSelectCluster(selectedClusterId === c.id ? null : c)}
            >
              <div style={{ fontWeight: 600, marginBottom: 2 }}>
                <i className={`bi ${c.id === 'cluster:internal' ? 'bi-hdd-network' : 'bi-question-circle'} me-1 text-secondary`} style={{ fontSize: 10 }} />
                {c.label}
              </div>
              <div className="text-muted" style={{ fontSize: 10 }}>
                {c.hostCount.toLocaleString()} hosts · {formatBytes(c.totalBytes)}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Hint */}
      {!isDrilled && (
        <div style={{
          position: 'absolute', bottom: 12, left: '50%', transform: 'translateX(-50%)',
          fontSize: 10, color: 'var(--tp-text-muted, #6c757d)',
          background: 'var(--tp-surface, #fff)', border: '1px solid var(--tp-border, #dee2e6)',
          borderRadius: 4, padding: '2px 8px', zIndex: 5, whiteSpace: 'nowrap',
        }}>
          Click a highlighted country to view city-level breakdown
        </div>
      )}

      {/* Legend */}
      <div style={{
        position: 'absolute', bottom: 12, right: 12,
        background: 'var(--tp-surface, #fff)', border: '1px solid var(--tp-border, #dee2e6)',
        borderRadius: 6, padding: '6px 10px', fontSize: 10,
        color: 'var(--tp-text-muted, #6c757d)', zIndex: 5,
      }}>
        {colorMode === 'traffic'
          ? <div>Dark blue = more traffic</div>
          : <div style={{ color: '#e74c3c' }}>● Red = has risk alerts</div>
        }
      </div>
    </div>
  );
}

// ── ISO numeric → alpha-2 lookup ──────────────────────────────────────────────
const isoNumericToAlpha2: Record<string, string> = {
  '4':'AF','8':'AL','12':'DZ','24':'AO','32':'AR','36':'AU','40':'AT','50':'BD',
  '56':'BE','64':'BT','68':'BO','76':'BR','100':'BG','116':'KH','120':'CM','124':'CA',
  '140':'CF','144':'LK','152':'CL','156':'CN','170':'CO','178':'CG','180':'CD','188':'CR',
  '191':'HR','192':'CU','196':'CY','203':'CZ','208':'DK','214':'DO','218':'EC','818':'EG',
  '222':'SV','231':'ET','246':'FI','250':'FR','266':'GA','276':'DE','288':'GH','300':'GR',
  '320':'GT','324':'GN','332':'HT','340':'HN','348':'HU','356':'IN','360':'ID','364':'IR',
  '368':'IQ','372':'IE','376':'IL','380':'IT','388':'JM','392':'JP','400':'JO','398':'KZ',
  '404':'KE','408':'KP','410':'KR','414':'KW','418':'LA','422':'LB','426':'LS','430':'LR',
  '434':'LY','440':'LT','442':'LU','450':'MG','454':'MW','458':'MY','466':'ML','484':'MX',
  '496':'MN','504':'MA','508':'MZ','516':'NA','524':'NP','528':'NL','540':'NC','554':'NZ',
  '558':'NI','562':'NE','566':'NG','578':'NO','586':'PK','591':'PA','598':'PG','600':'PY',
  '604':'PE','608':'PH','616':'PL','620':'PT','630':'PR','634':'QA','642':'RO','643':'RU',
  '646':'RW','682':'SA','686':'SN','694':'SL','706':'SO','710':'ZA','724':'ES','729':'SD',
  '752':'SE','756':'CH','760':'SY','762':'TJ','764':'TH','768':'TG','788':'TN','792':'TR',
  '800':'UG','804':'UA','784':'AE','826':'GB','840':'US','858':'UY','860':'UZ','862':'VE',
  '704':'VN','887':'YE','894':'ZM','716':'ZW','702':'SG','104':'MM',
};
