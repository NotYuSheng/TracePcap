/**
 * Shared by every table in the app, so its arithmetic is repeated everywhere at once. The
 * "Showing X to Y of Z" line is the only place a user can check that a filter did what they
 * expected, which makes an off-by-one here quietly corrosive rather than cosmetic.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { Pagination } from '../Pagination'

function renderPager(props: Partial<Parameters<typeof Pagination>[0]> = {}) {
  const onPageChange = vi.fn()
  const onPageSizeChange = vi.fn()
  const { container } = render(
    <Pagination
      currentPage={1}
      totalPages={4}
      totalItems={100}
      pageSize={25}
      onPageChange={onPageChange}
      onPageSizeChange={onPageSizeChange}
      {...props}
    />
  )
  return { onPageChange, onPageSizeChange, container }
}

describe('Pagination', () => {
  it('renders nothing when there are no pages', () => {
    const { container } = renderPager({ totalPages: 0 })

    // An empty pager below an empty table is noise; the table already says it is empty.
    expect(container).toBeEmptyDOMElement()
  })

  it('counts from one on the first page', () => {
    renderPager({ currentPage: 1, pageSize: 25, totalItems: 100 })

    // Off by one here is the classic: "Showing 0 to 25" or "1 to 26" both look plausible.
    expect(screen.getByText(/Showing 1 to 25 of 100 items/)).toBeInTheDocument()
  })

  it('offsets the range on a later page', () => {
    renderPager({ currentPage: 3, pageSize: 25, totalItems: 100 })

    expect(screen.getByText(/Showing 51 to 75 of 100 items/)).toBeInTheDocument()
  })

  it('clamps the last page to the item count', () => {
    renderPager({ currentPage: 3, totalPages: 3, pageSize: 25, totalItems: 60 })

    // Without the clamp this reads "Showing 51 to 75 of 60", which is visibly wrong and
    // undermines confidence in every other number on the page.
    expect(screen.getByText(/Showing 51 to 60 of 60 items/)).toBeInTheDocument()
  })

  it('shows a zero range rather than "1 to 0" when there is nothing to show', () => {
    renderPager({ totalPages: 1, totalItems: 0 })

    expect(screen.getByText(/Showing 0 to 0 of 0 items/)).toBeInTheDocument()
  })

  it('reports the chosen page to the caller', async () => {
    const { onPageChange } = renderPager()

    await userEvent.click(screen.getByText('3'))

    expect(onPageChange).toHaveBeenCalledWith(3)
  })

  it('reports a page size change', async () => {
    const { onPageSizeChange } = renderPager()

    await userEvent.selectOptions(screen.getByLabelText(/Items per page/), '50')

    expect(onPageSizeChange).toHaveBeenCalledWith(50)
  })

  it('hides the page-size selector when the caller cannot handle it', () => {
    render(
      <Pagination currentPage={1} totalPages={4} totalItems={100} onPageChange={vi.fn()} />
    )

    // Offering a control that does nothing is worse than not offering it.
    expect(screen.queryByLabelText(/Items per page/)).not.toBeInTheDocument()
  })

  it('offers the page sizes it was given', () => {
    renderPager({ pageSizeOptions: [5, 10] })

    expect(screen.getByRole('option', { name: '5' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: '25' })).not.toBeInTheDocument()
  })

  it('marks itself compact for narrow containers', () => {
    const { container } = renderPager({ compact: true })

    // The drift panels put this in a ~250px column; the compact class is what stops the pager
    // wrapping onto three rows there.
    expect(container.querySelector('.pagination-container--compact')).toBeInTheDocument()
  })
})
