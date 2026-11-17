import { describe, expect, it } from 'vitest'
import { create } from 'zustand'
import { createNodeLabelSlice, DEFAULT_NODE_LABEL_CONFIG, normalizeNodeLabelConfig, type NodeLabelSlice } from '../nodeLabelSlice'

describe('how the map routes edges, kept with the label settings', () => {
  it('survives loading a saved config', () => {
    expect(normalizeNodeLabelConfig({ ...DEFAULT_NODE_LABEL_CONFIG, edgeRouting: 'lanes' }).edgeRouting).toBe('lanes')
  })

  it('drops a value it does not know (falls back to bending)', () => {
    const cfg = { ...DEFAULT_NODE_LABEL_CONFIG, edgeRouting: 'zigzag' } as unknown as typeof DEFAULT_NODE_LABEL_CONFIG
    expect(normalizeNodeLabelConfig(cfg).edgeRouting).toBeUndefined()
  })

  it('is not undone by resetting the labels', () => {
    const store = create<NodeLabelSlice>()((...a) => createNodeLabelSlice(...a))
    store.getState().setNodeLabelConfig({ ...DEFAULT_NODE_LABEL_CONFIG, customText: ['x'], edgeRouting: 'straight' })
    store.getState().resetNodeLabelConfig()
    expect(store.getState().nodeLabelConfig.customText).toEqual([])
    expect(store.getState().nodeLabelConfig.edgeRouting).toBe('straight')
  })
})
