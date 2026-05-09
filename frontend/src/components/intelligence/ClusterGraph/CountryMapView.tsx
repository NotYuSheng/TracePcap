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

// ── Color helpers ─────────────────────────────────────────────────────────────
function trafficColor(ratio: number): string {
  const r = Math.round(208 - ratio * (208 - 21));
  const g = Math.round(228 - ratio * (228 - 101));
  const b = Math.round(247 - ratio * (247 - 192));
  return `rgb(${r},${g},${b})`;
}

type ColorMode = 'risk' | 'traffic';

// ── Types ─────────────────────────────────────────────────────────────────────
interface PositionedCluster {
  id: string;
  lon: number;
  lat: number;
}

// ── Country centre for drill-down zoom ───────────────────────────────────────
// Returns [centerLon, centerLat, zoom] for a given country code
function countryView(cc: string): [number, number, number] {
  const c = CENTROID_MAP[cc];
  if (!c) return [0, 20, 2];
  // Simple heuristic zoom based on country size (can be refined)
  const smallCountries = new Set([
    'SG','BH','BN','QA','KW','MT','LU','LI','AD','MC','SM','VA',
    'MV','SC','MU','BB','GD','LC','VC','DM','AG','KN','TT','JM',
  ]);
  const largeCountries = new Set(['RU','CA','US','CN','BR','AU','IN','AR','KZ']);
  const zoom = smallCountries.has(cc) ? 8 : largeCountries.has(cc) ? 3 : 5;
  return [c[1], c[0], zoom];
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
  // ── Drill-down state ───────────────────────────────────────────────────────
  // When a country is clicked we drill into it and show city clusters
  const [drilledCountryId, setDrilledCountryId] = useState<string | null>(null);
  const [cityData, setCityData] = useState<ClusterGraphResponse | null>(null);
  const [cityLoading, setCityLoading] = useState(false);

  const [zoom, setZoom] = useState(1);
  const [center, setCenter] = useState<[number, number]>([0, 20]);

  const MAX_BYTES = Math.max(...data.clusters.map(c => c.totalBytes), 1);

  // ── Build world-level positions ────────────────────────────────────────────
  const { worldClusters, internalCluster, unknownCluster } = useMemo(() => {
    const geo: PositionedCluster[] = [];
    let internal: ClusterNode | undefined;
    let unknown: ClusterNode | undefined;

    for (const c of data.clusters) {
      if (c.id === 'cluster:internal') { internal = c; continue; }
      if (c.id === 'cluster:unknown') { unknown = c; continue; }
      const cc = c.id.startsWith('country:') ? c.id.slice(8) : null;
      if (!cc) continue;
      // Prefer MMDB lat/lon if available, fall back to static centroid
      if (c.lat != null && c.lon != null) {
        geo.push({ id: c.id, lon: c.lon, lat: c.lat });
      } else {
        const coord = CENTROID_MAP[cc];
        if (coord) geo.push({ id: c.id, lon: coord[1], lat: coord[0] });
      }
    }
    return { worldClusters: geo, internalCluster: internal, unknownCluster: unknown };
  }, [data.clusters]);

  const clusterById = new Map(data.clusters.map(c => [c.id, c]));

  // ── Fetch city data when drilling into a country ───────────────────────────
  useEffect(() => {
    if (!drilledCountryId) { setCityData(null); return; }
    setCityLoading(true);
    intelligenceService.getClusters(fileId, 'city')
      .then(d => setCityData(d))
      .catch(() => setCityData(null))
      .finally(() => setCityLoading(false));
  }, [drilledCountryId, fileId]);

  // Filter city clusters to the drilled country
  const drilledCC = drilledCountryId?.startsWith('country:')
    ? drilledCountryId.slice(8) : null;

  const cityClusters: PositionedCluster[] = useMemo(() => {
    if (!cityData || !drilledCC) return [];
    return cityData.clusters
      .filter(c => c.id.startsWith(`city:${drilledCC}:`))
      .filter(c => c.lat != null && c.lon != null)
      .map(c => ({ id: c.id, lon: c.lon!, lat: c.lat! }));
  }, [cityData, drilledCC]);

  const cityClusterById = new Map((cityData?.clusters ?? []).map(c => [c.id, c]));
  const cityMaxBytes = Math.max(...(cityData?.clusters ?? []).map(c => c.totalBytes), 1);

  // ── Click handlers ─────────────────────────────────────────────────────────
  function handleCountryClick(clusterId: string) {
    if (drilledCountryId) {
      // Already drilled — clicking the same country closes drill-down,
      // clicking another country switches to that one
      if (drilledCountryId === clusterId) {
        exitDrillDown();
        return;
      }
    }
    // Drill into this country
    const cc = clusterId.startsWith('country:') ? clusterId.slice(8) : null;
    if (!cc) return;
    const [cLon, cLat, cZoom] = countryView(cc);
    setCenter([cLon, cLat]);
    setZoom(cZoom);
    setDrilledCountryId(clusterId);
    onSelectCluster(null); // clear world-level selection
  }

  function handleCityClick(clusterId: string) {
    const c = cityClusterById.get(clusterId);
    if (!c) return;
    onSelectCluster(selectedClusterId === clusterId ? null : c);
  }

  function exitDrillDown() {
    setDrilledCountryId(null);
    setCityData(null);
    setZoom(1);
    setCenter([0, 20]);
    onSelectCluster(null);
  }

  // ── Fill for country geography polygons ───────────────────────────────────
  function countryFill(isoNumeric: string): string {
    // world-atlas uses numeric ISO codes; we need to match our alpha-2 clusters
    // Colour active-cluster countries; grey others
    // We'll colour based on whether any cluster matches
    const matchingCluster = data.clusters.find(
      c => c.id.startsWith('country:') && isoNumericToAlpha2[isoNumeric] === c.id.slice(8)
    );
    if (!matchingCluster) return '#e9ecef';
    if (colorMode === 'traffic') return trafficColor(matchingCluster.totalBytes / MAX_BYTES);
    if (matchingCluster.riskCount > 0) return '#fce8e6';
    return '#d6e4f7';
  }

  // ── Marker colour ──────────────────────────────────────────────────────────
  function markerFill(cluster: ClusterNode, maxBytes: number): string {
    if (colorMode === 'traffic') return trafficColor(cluster.totalBytes / maxBytes);
    return cluster.riskCount > 0 ? '#e74c3c' : '#1a73e8';
  }

  const MARKER_R = 7;
  const isDrilled = drilledCountryId !== null;

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>

      {/* Breadcrumb / back button when drilled */}
      {isDrilled && (
        <div
          style={{
            position: 'absolute', top: 10, left: 10, zIndex: 20,
            display: 'flex', alignItems: 'center', gap: 8,
          }}
        >
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
          {cityLoading && (
            <span className="spinner-border spinner-border-sm text-primary" style={{ width: 14, height: 14, borderWidth: 2 }} />
          )}
        </div>
      )}

      {/* Zoom controls */}
      <div
        style={{
          position: 'absolute', bottom: 12, left: 12, zIndex: 10,
          display: 'flex', flexDirection: 'column', gap: 4,
        }}
      >
        <button
          className="btn btn-sm btn-light border"
          style={{ width: 28, height: 28, padding: 0, lineHeight: 1 }}
          onClick={() => setZoom(z => Math.min(z * 1.5, 20))}
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
          onClick={() => { exitDrillDown(); }}
          title="Reset view"
        >⌂</button>
      </div>

      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 130 }}
        style={{ width: '100%', height: '100%', background: 'var(--tp-surface, #fff)' }}
      >
        <ZoomableGroup
          zoom={zoom}
          center={center}
          onMoveEnd={({ zoom: z, coordinates }) => {
            setZoom(z);
            setCenter(coordinates as [number, number]);
          }}
        >
          {/* Map background — colour countries that have clusters */}
          <Geographies geography={worldTopojson}>
            {({ geographies }) =>
              geographies.map(geo => {
                const isoNum = String(geo.id ?? geo.properties?.['iso_n3'] ?? '');
                const fill = countryFill(isoNum);
                const isActiveDrilled = isDrilled &&
                  isoNum === alpha2ToIsoNumeric[drilledCC ?? ''];
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    style={{
                      default: {
                        fill,
                        stroke: isActiveDrilled ? '#0d6efd' : '#ced4da',
                        strokeWidth: isActiveDrilled ? 1.5 : 0.3,
                        outline: 'none',
                      },
                      hover: { fill: fill === '#e9ecef' ? '#dee2e6' : fill, outline: 'none' },
                      pressed: { fill, outline: 'none' },
                    }}
                  />
                );
              })
            }
          </Geographies>

          {/* World-level country markers (hidden when drilled in to reduce clutter) */}
          {!isDrilled && worldClusters.map(({ id, lon, lat }) => {
            const cluster = clusterById.get(id);
            if (!cluster) return null;
            const r = MARKER_R / zoom;
            const isSelected = selectedClusterId === id;
            const fill = markerFill(cluster, MAX_BYTES);
            return (
              <Marker key={id} coordinates={[lon, lat]}
                onClick={() => {
                  onSelectCluster(isSelected ? null : cluster);
                  handleCountryClick(id);
                }}
              >
                <circle
                  r={r}
                  fill={fill}
                  stroke={isSelected ? '#0d6efd' : cluster.riskCount > 0 && colorMode !== 'traffic' ? '#e74c3c' : '#fff'}
                  strokeWidth={(isSelected ? 2 : 1) / zoom}
                  style={{ cursor: 'pointer' }}
                />
                {cluster.riskCount > 0 && colorMode !== 'traffic' && (
                  <text textAnchor="middle" y={-r - 2 / zoom}
                    style={{ fontSize: 8 / zoom, fill: '#e74c3c', pointerEvents: 'none' }}>▲</text>
                )}
                <text textAnchor="middle" y={r + 9 / zoom}
                  style={{
                    fontSize: 8 / zoom, fill: '#212529', fontWeight: isSelected ? 700 : 400,
                    pointerEvents: 'none', paintOrder: 'stroke',
                    stroke: '#fff', strokeWidth: 3 / zoom, strokeLinejoin: 'round',
                  }}
                >
                  {cluster.label.length > 20 ? cluster.label.slice(0, 18) + '…' : cluster.label}
                </text>
              </Marker>
            );
          })}

          {/* City-level markers (only when drilled into a country) */}
          {isDrilled && cityClusters.map(({ id, lon, lat }) => {
            const cluster = cityClusterById.get(id);
            if (!cluster) return null;
            const r = MARKER_R / zoom;
            const isSelected = selectedClusterId === id;
            const fill = markerFill(cluster, cityMaxBytes);
            return (
              <Marker key={id} coordinates={[lon, lat]}
                onClick={() => handleCityClick(id)}
              >
                <circle
                  r={r}
                  fill={fill}
                  stroke={isSelected ? '#0d6efd' : cluster.riskCount > 0 && colorMode !== 'traffic' ? '#e74c3c' : '#fff'}
                  strokeWidth={(isSelected ? 2 : 1) / zoom}
                  style={{ cursor: 'pointer' }}
                />
                {cluster.riskCount > 0 && colorMode !== 'traffic' && (
                  <text textAnchor="middle" y={-r - 2 / zoom}
                    style={{ fontSize: 8 / zoom, fill: '#e74c3c', pointerEvents: 'none' }}>▲</text>
                )}
                <text textAnchor="middle" y={r + 9 / zoom}
                  style={{
                    fontSize: 9 / zoom, fill: '#212529', fontWeight: isSelected ? 700 : 400,
                    pointerEvents: 'none', paintOrder: 'stroke',
                    stroke: '#fff', strokeWidth: 3 / zoom, strokeLinejoin: 'round',
                  }}
                >
                  {/* Strip "City Name, Country" → just "City Name" */}
                  {cluster.label.split(',')[0]}
                </text>
              </Marker>
            );
          })}

          {/* No city data notice when drilled but no cities resolved */}
          {isDrilled && !cityLoading && cityClusters.length === 0 && cityData && (
            <Marker coordinates={center}>
              <foreignObject x={-100} y={-20} width={200} height={40}>
                <div style={{ textAlign: 'center', fontSize: 11, color: '#6c757d', background: 'rgba(255,255,255,0.85)', borderRadius: 4, padding: '2px 8px' }}>
                  No city-level data available
                </div>
              </foreignObject>
            </Marker>
          )}
        </ZoomableGroup>
      </ComposableMap>

      {/* Internal / Unknown floating card (world view only) */}
      {!isDrilled && (internalCluster || unknownCluster) && (
        <div style={{ position: 'absolute', top: 10, left: 10, display: 'flex', flexDirection: 'column', gap: 6, zIndex: 5 }}>
          {[internalCluster, unknownCluster].filter(Boolean).map(c => c && (
            <div
              key={c.id}
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

      {/* Hint: click a country to drill in */}
      {!isDrilled && worldClusters.length > 0 && (
        <div style={{
          position: 'absolute', bottom: 12, left: '50%', transform: 'translateX(-50%)',
          fontSize: 10, color: 'var(--tp-text-muted, #6c757d)',
          background: 'var(--tp-surface, #fff)', border: '1px solid var(--tp-border, #dee2e6)',
          borderRadius: 4, padding: '2px 8px', zIndex: 5, whiteSpace: 'nowrap',
        }}>
          Click a country to drill into city-level view
        </div>
      )}

      {/* Legend */}
      <div
        style={{
          position: 'absolute', bottom: 12, right: 12,
          background: 'var(--tp-surface, #fff)',
          border: '1px solid var(--tp-border, #dee2e6)',
          borderRadius: 6, padding: '6px 10px', fontSize: 10,
          color: 'var(--tp-text-muted, #6c757d)', zIndex: 5,
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

// ── ISO numeric ↔ alpha-2 lookup tables (subset for world-atlas 110m/50m) ────
// world-atlas uses ISO 3166-1 numeric as `geo.id`; we need alpha-2 to match cluster IDs.
// Generated from https://www.iban.com/country-codes (subset of commonly-seen countries).
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
  '704':'VN','887':'YE','894':'ZM','716':'ZW','566':'NG','702':'SG','104':'MM','012':'DZ',
};
// Reverse map
const alpha2ToIsoNumeric: Record<string, string> = Object.fromEntries(
  Object.entries(isoNumericToAlpha2).map(([num, a2]) => [a2, num])
);
