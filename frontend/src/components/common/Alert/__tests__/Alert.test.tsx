/**
 * Regression cover for #384.
 *
 * React 19 ignores `defaultProps` on function components, but SGDS's Alert relies on them for
 * `show` and `transition`. Without this wrapper `show` is undefined, SGDS returns null, and the
 * page renders an empty invisible container — every error message in the app silently vanishes
 * while the code that raised it looks correct.
 *
 * That failure mode is the reason this tiny component deserves tests: nothing throws, nothing
 * logs, the alert simply is not there.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Alert } from '../Alert'

describe('Alert', () => {
  it('renders its content without being told to show', () => {
    render(<Alert variant="danger">Analysis failed on server</Alert>)

    // The whole point of the wrapper. If this fails, every error banner in the app is invisible.
    expect(screen.getByText('Analysis failed on server')).toBeInTheDocument()
  })

  it('still honours an explicit show={false}', () => {
    render(<Alert show={false}>Should not appear</Alert>)

    // The default must not become a hard-coded true, or callers lose the ability to hide one.
    expect(screen.queryByText('Should not appear')).not.toBeInTheDocument()
  })

  it('honours an explicit show={true}', () => {
    render(<Alert show>Explicitly shown</Alert>)

    expect(screen.getByText('Explicitly shown')).toBeInTheDocument()
  })

  it('renders immediately rather than fading in', () => {
    render(<Alert variant="warning">Immediate</Alert>)

    // transition defaults to false because react-transition-group's Fade also misbehaves under
    // React 19. With a transition the element is present but starts hidden, which reintroduces
    // the same "message never appeared" symptom by a different route.
    const alert = screen.getByText('Immediate').closest('.alert')
    expect(alert).not.toHaveClass('fade')
  })

  it('keeps the variant class so severity is still conveyed', () => {
    render(<Alert variant="danger">Bad news</Alert>)

    // An alert that renders but looks neutral is nearly as bad as one that does not render.
    expect(screen.getByText('Bad news').closest('.alert')).toHaveClass('alert-danger')
  })

  it('exposes the Heading and Link subcomponents the wrapper re-attaches', () => {
    render(
      <Alert variant="info">
        <Alert.Heading>Heads up</Alert.Heading>
        <Alert.Link href="/docs">docs</Alert.Link>
      </Alert>
    )

    // Object.assign re-attaches these; forgetting one is a runtime "is not a component" crash
    // at the call site rather than a compile error.
    expect(screen.getByText('Heads up')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'docs' })).toBeInTheDocument()
  })
})
