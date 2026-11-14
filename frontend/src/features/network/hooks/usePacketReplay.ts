import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { groupMoments, momentIndexOf, packetReplayService, type Moment, type ReplayPacket } from '../services/packetReplay';

const PAGE_SIZE = 2000;
/** Pages kept in memory; older ones are dropped as the replay moves on. */
const MAX_PAGES = 6;
/** Fetch the next page when the playhead gets this close to the end of what's loaded. */
const AHEAD = 100;

export type ReplayStatus = 'idle' | 'loading' | 'ready' | 'pruned' | 'error';

/**
 * Plays a capture back packet by packet: loads pages of packets around the playhead, groups them
 * into moments (packets at the same instant play together), and steps through the moments on its
 * own clock (`speed` moments a second) or by hand.
 */
export function usePacketReplay(fileId: string, enabled: boolean) {
  const [packets, setPackets] = useState<ReplayPacket[]>([]);
  const [pages, setPages] = useState<{ first: number; last: number }>({ first: 0, last: 0 });
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [status, setStatus] = useState<ReplayStatus>('idle');
  /** The playhead: the first packet number of the current moment. */
  const [cursor, setCursor] = useState(1);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(2);
  const loadingRef = useRef(false);

  const moments = useMemo(() => groupMoments(packets), [packets]);
  const index = moments.length ? momentIndexOf(moments, cursor) : -1;
  const moment: Moment | null = index >= 0 ? moments[index] : null;

  const fail = (e: unknown) => {
    const code = (e as { response?: { status?: number } })?.response?.status;
    setStatus(code === 404 ? 'pruned' : 'error');
    setPlaying(false);
  };

  /** Replace what's loaded with the page holding `at` (epoch ms), or page 1. */
  const loadAt = useCallback(
    async (at?: number) => {
      loadingRef.current = true;
      setStatus(s => (s === 'ready' ? s : 'loading'));
      try {
        const r = await packetReplayService.page(fileId, 1, PAGE_SIZE, at);
        setPackets(r.packets);
        setPages({ first: r.page, last: r.page });
        setTotal(r.total);
        setTotalPages(r.totalPages);
        const start = at == null ? r.packets[0] : r.packets.find(p => p.t >= at) ?? r.packets[r.packets.length - 1];
        setCursor(start?.number ?? 1);
        setStatus('ready');
      } catch (e) {
        fail(e);
      } finally {
        loadingRef.current = false;
      }
    },
    [fileId],
  );

  // Start (or restart, for another capture) when replay is switched on.
  useEffect(() => {
    if (!enabled) {
      setPlaying(false);
      return;
    }
    setPackets([]);
    setStatus('loading');
    void loadAt();
  }, [enabled, loadAt]);

  // Keep a page ahead of the playhead loaded; drop pages far behind.
  useEffect(() => {
    if (!enabled || status !== 'ready' || loadingRef.current) return;
    if (pages.last >= totalPages || index < moments.length - AHEAD) return;
    loadingRef.current = true;
    packetReplayService
      .page(fileId, pages.last + 1, PAGE_SIZE)
      .then(r => {
        setPackets(prev => {
          const next = [...prev, ...r.packets];
          return pages.last - pages.first + 1 >= MAX_PAGES ? next.slice(PAGE_SIZE) : next;
        });
        setPages(p => ({ first: p.last - p.first + 1 >= MAX_PAGES ? p.first + 1 : p.first, last: r.page }));
      })
      .catch(fail)
      .finally(() => {
        loadingRef.current = false;
      });
  }, [enabled, status, index, moments.length, pages, totalPages, fileId]);

  const step = useCallback(
    async (by: number) => {
      if (!moments.length) return;
      let target = index + by;
      if (target < 0 && pages.first > 1 && !loadingRef.current) {
        // Back past what's loaded: fetch the page before and step into it.
        loadingRef.current = true;
        try {
          const r = await packetReplayService.page(fileId, pages.first - 1, PAGE_SIZE);
          const before = groupMoments(r.packets);
          setPackets(prev => [...r.packets, ...prev]);
          setPages(p => ({ ...p, first: r.page }));
          target = Math.max(0, before.length + target);
          setCursor((before[target] ?? before[0]).packets[0].number);
        } catch (e) {
          fail(e);
        } finally {
          loadingRef.current = false;
        }
        return;
      }
      target = Math.min(Math.max(0, target), moments.length - 1);
      setCursor(moments[target].packets[0].number);
    },
    [moments, index, pages.first, fileId],
  );

  const atEnd = moment != null && index === moments.length - 1 && pages.last >= totalPages;

  // The replay's own clock.
  const stepRef = useRef(step);
  stepRef.current = step;
  const atEndRef = useRef(atEnd);
  atEndRef.current = atEnd;
  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      if (atEndRef.current) {
        setPlaying(false);
        return;
      }
      void stepRef.current(1);
    }, 1000 / speed);
    return () => clearInterval(id);
  }, [playing, speed]);

  const seek = useCallback(
    (at: number) => {
      // Inside what's loaded: just move. Else load the page there.
      if (packets.length && at >= packets[0].t && at <= packets[packets.length - 1].t) {
        const p = packets.find(x => x.t >= at);
        if (p) setCursor(p.number);
        return;
      }
      void loadAt(at);
    },
    [packets, loadAt],
  );

  return {
    status,
    moment,
    /** Position of the moment's first packet among all packets, 1-based. */
    position: moment?.packets[0].number ?? 0,
    total,
    playing,
    play: () => {
      if (atEnd) void loadAt();
      setPlaying(true);
    },
    pause: () => setPlaying(false),
    step: (by: number) => {
      setPlaying(false);
      void step(by);
    },
    seek: (at: number) => {
      setPlaying(false);
      seek(at);
    },
    speed,
    setSpeed,
  };
}

export type PacketReplay = ReturnType<typeof usePacketReplay>;
