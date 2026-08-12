import '@testing-library/jest-dom/vitest'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { server } from './msw'

// Service tests intercept HTTP with MSW. Starting the server here rather than per-file keeps
// individual tests to their handlers. 'error' on an unhandled request is deliberate: a call to
// a URL no handler matches fails loudly instead of hanging, so a wrong path is a test failure.
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
