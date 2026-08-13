import { describe, expect, it } from 'vitest'

import { severityBadgeBg, severityHex, severityIcon } from '../severityColors'

describe('severityColors', () => {
  it('gives each severity one colour across every panel', () => {
    // Four maps disagreed before this. The specific values matter less than there being one
    // answer: an operator comparing the event list with the security tab was comparing colours
    // that meant the same thing and looked different.
    expect(severityHex('CRITICAL')).toBe('#dc3545')
    expect(severityHex('WARNING')).toBe('#fd7e14')
    expect(severityHex('INFO')).toBe('#6c757d')
  })

  it('does not render INFO as green', () => {
    // The snapshot modal drew INFO in #2ecc71. Green is the success colour everywhere else in
    // the app, so an informational event read as "this is fine" in that one panel.
    expect(severityHex('INFO')).not.toBe('#2ecc71')
  })

  it('keeps WARNING distinguishable from CRITICAL', () => {
    // Bootstrap's text-warning is #ffc107, a yellow that reads as much softer than the orange
    // the other panels used. Pinned so the two stay visually ordered.
    expect(severityHex('WARNING')).not.toBe(severityHex('CRITICAL'))
    expect(severityHex('WARNING')).not.toBe('#ffc107')
  })

  it('falls back visibly for an unknown severity', () => {
    // A new severity from the backend must not render transparent or undefined.
    expect(severityHex('SOMETHING_NEW')).toBe('#6c757d')
    expect(severityHex(null)).toBe('#6c757d')
    expect(severityHex(undefined)).toBe('#6c757d')
  })

  it('pairs an icon with each severity, and a visible fallback', () => {
    expect(severityIcon('CRITICAL')).toBe('bi-exclamation-circle-fill')
    expect(severityIcon('WARNING')).toBe('bi-exclamation-triangle-fill')
    expect(severityIcon('INFO')).toBe('bi-info-circle-fill')
    expect(severityIcon('SOMETHING_NEW')).toBe('bi-circle-fill')
  })

  it('maps to Bootstrap badge variants for the legend copy', () => {
    expect(severityBadgeBg('CRITICAL')).toBe('danger')
    expect(severityBadgeBg('WARNING')).toBe('warning')
    expect(severityBadgeBg('INFO')).toBe('secondary')
  })
})
