/**
 * Per-snapshot history for an IP or a MAC across a monitor network. This is the view an analyst
 * uses to answer "did this address change hands", so the two halves are mirror images: for an IP,
 * which MACs claimed it; for a DEVICE, which IPs that MAC used. More than one on either side is
 * the conflict worth seeing.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types'
import { server } from '@/test/msw'
import { useIpSnapshotHistory } from '../useIpSnapshotHistory'

const snapshot = (id: string, fileId: string, order: number) =>
  ({ id, fileId, snapshotOrder: order }) as NetworkSnapshot

/**
 * Serves the three endpoints the hook fans out to, keyed by fileId so each snapshot can carry
 * different data.
 */
function serve(byFile: Record<string, { classifications?: unknown[]; observations?: unknown[] }>) {
  server.use(
    http.get('*/files/:fileId/host-classifications', ({ params }) =>
      HttpResponse.json(byFile[params.fileId as string]?.classifications ?? [])
    ),
    http.get('*/files/:fileId/ip-mac-observations', ({ params }) =>
      HttpResponse.json(byFile[params.fileId as string]?.observations ?? [])
    ),
    http.get('*/node-roles', () => new HttpResponse(null, { status: 404 })),
    http.get('*/conversations/*', () => HttpResponse.json({ data: [] }))
  )
}

describe('useIpSnapshotHistory', () => {
  it('keeps only the snapshots where the IP appeared', async () => {
    serve({
      'file-1': { classifications: [{ ip: '10.0.0.1', mac: 'aa:bb:cc:dd:ee:ff' }] },
      'file-2': { classifications: [{ ip: '10.0.0.9', mac: '11:22:33:44:55:66' }] },
    })

    const { result } = renderHook(() =>
      useIpSnapshotHistory('IP', '10.0.0.1', [
        snapshot('s1', 'file-1', 1),
        snapshot('s2', 'file-2', 2),
      ])
    )

    // A row per snapshot the host was absent from would imply it vanished, when it was simply
    // never captured there.
    await waitFor(() => expect(result.current.ipSnapHistory).toHaveLength(1))
    expect(result.current.ipSnapHistory[0].snap.id).toBe('s1')
  })

  it('orders history by snapshotOrder, not by the order snapshots were passed in', async () => {
    serve({
      'file-1': { classifications: [{ ip: '10.0.0.1', mac: 'aa:aa:aa:aa:aa:aa' }] },
      'file-2': { classifications: [{ ip: '10.0.0.1', mac: 'bb:bb:bb:bb:bb:bb' }] },
    })

    const { result } = renderHook(() =>
      useIpSnapshotHistory('IP', '10.0.0.1', [
        snapshot('s2', 'file-2', 2),
        snapshot('s1', 'file-1', 1),
      ])
    )

    // The history reads as a timeline, so a reversed row order tells the opposite story about
    // which MAC held the address first.
    await waitFor(() => expect(result.current.ipSnapHistory).toHaveLength(2))
    expect(result.current.ipSnapHistory.map(e => e.snap.id)).toEqual(['s1', 's2'])
  })

  it('lists every MAC that claimed the IP in a snapshot', async () => {
    serve({
      'file-1': {
        classifications: [{ ip: '10.0.0.1', mac: 'aa:aa:aa:aa:aa:aa' }],
        observations: [{ ip: '10.0.0.1', macs: ['aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb'] }],
      },
    })

    const { result } = renderHook(() =>
      useIpSnapshotHistory('IP', '10.0.0.1', [snapshot('s1', 'file-1', 1)])
    )

    // More than one MAC on an address is the overlap conflict this view exists to surface.
    await waitFor(() => expect(result.current.ipSnapHistory).toHaveLength(1))
    expect(result.current.ipSnapHistory[0].macs).toEqual([
      'aa:aa:aa:aa:aa:aa',
      'bb:bb:bb:bb:bb:bb',
    ])
  })

  it('matches a MAC case-insensitively', async () => {
    serve({
      'file-1': {
        classifications: [{ ip: '10.0.0.5', mac: 'AA:BB:CC:DD:EE:FF' }],
        observations: [{ ip: '10.0.0.5', macs: ['AA:BB:CC:DD:EE:FF'] }],
      },
    })

    const { result } = renderHook(() =>
      useIpSnapshotHistory('DEVICE', 'aa:bb:cc:dd:ee:ff', [snapshot('s1', 'file-1', 1)])
    )

    // Captures and the UI disagree on MAC casing routinely. An exact match would show a device
    // as absent from every snapshot it is actually in.
    await waitFor(() => expect(result.current.ipSnapHistory).toHaveLength(1))
    expect(result.current.ipSnapHistory[0].ips).toEqual(['10.0.0.5'])
  })

  it.each(['APPLICATION', 'PROTOCOL'] as const)('does not fetch for a %s entity', async type => {
    let called = false
    server.use(
      http.get('*/files/:fileId/host-classifications', () => {
        called = true
        return HttpResponse.json([])
      })
    )

    const { result } = renderHook(() =>
      useIpSnapshotHistory(type, 'TLS', [snapshot('s1', 'file-1', 1)])
    )

    // Snapshot history is about addresses; an application has none.
    await waitFor(() => expect(result.current.ipHistoryLoading).toBe(false))
    expect(called).toBe(false)
  })

  it('does nothing without snapshots', async () => {
    const { result } = renderHook(() => useIpSnapshotHistory('IP', '10.0.0.1', []))

    await waitFor(() => expect(result.current.ipHistoryLoading).toBe(false))
    expect(result.current.ipSnapHistory).toEqual([])
  })

  it('keeps the other snapshots when one snapshot fails to load', async () => {
    server.use(
      http.get('*/files/file-1/host-classifications', () =>
        HttpResponse.json({ message: 'boom' }, { status: 500 })
      ),
      http.get('*/files/file-2/host-classifications', () =>
        HttpResponse.json([{ ip: '10.0.0.1', mac: 'bb:bb:bb:bb:bb:bb' }])
      ),
      http.get('*/files/:fileId/ip-mac-observations', () => HttpResponse.json([])),
      http.get('*/node-roles', () => new HttpResponse(null, { status: 404 })),
      http.get('*/conversations/*', () => HttpResponse.json({ data: [] }))
    )

    const { result } = renderHook(() =>
      useIpSnapshotHistory('IP', '10.0.0.1', [
        snapshot('s1', 'file-1', 1),
        snapshot('s2', 'file-2', 2),
      ])
    )

    // Each snapshot is fetched independently and its failure caught, so one bad file does not
    // blank a history spanning months.
    await waitFor(() => expect(result.current.ipSnapHistory).toHaveLength(1))
    expect(result.current.ipSnapHistory[0].snap.id).toBe('s2')
  })
})
