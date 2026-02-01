import React from 'react'
import './Pagination.css'

interface PaginationProps {
  currentPage: number
  totalPages: number
  totalItems?: number
  pageSize?: number
  onPageChange: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
  pageSizeOptions?: number[]
  showPageSizeSelector?: boolean
}

export const Pagination: React.FC<PaginationProps> = ({
  currentPage,
  totalPages,
  totalItems = 0,
  pageSize = 25,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 25, 50, 100],
  showPageSizeSelector = true,
}) => {
  const startItem = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1
  const endItem = Math.min(currentPage * pageSize, totalItems)

  const handlePrevious = () => {
    if (currentPage > 1) {
      onPageChange(currentPage - 1)
    }
  }

  const handleNext = () => {
    if (currentPage < totalPages) {
      onPageChange(currentPage + 1)
    }
  }

  const handlePageSizeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newPageSize = parseInt(e.target.value, 10)
    if (onPageSizeChange) {
      onPageSizeChange(newPageSize)
    }
  }

  // Generate page numbers to display
  const getPageNumbers = () => {
    const pages: (number | string)[] = []
    const maxPagesToShow = 5

    if (totalPages <= maxPagesToShow) {
      // Show all pages if total is small
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i)
      }
    } else {
      // Always show first page
      pages.push(1)

      // Calculate range around current page
      let startPage = Math.max(2, currentPage - 1)
      let endPage = Math.min(totalPages - 1, currentPage + 1)

      // Adjust range if current page is near start or end
      if (currentPage <= 3) {
        endPage = 4
      } else if (currentPage >= totalPages - 2) {
        startPage = totalPages - 3
      }

      // Add ellipsis if needed
      if (startPage > 2) {
        pages.push('...')
      }

      // Add middle pages
      for (let i = startPage; i <= endPage; i++) {
        pages.push(i)
      }

      // Add ellipsis if needed
      if (endPage < totalPages - 1) {
        pages.push('...')
      }

      // Always show last page
      pages.push(totalPages)
    }

    return pages
  }

  if (totalPages === 0) {
    return null
  }

  return (
    <div className="pagination-container">
      <div className="pagination-info">
        Showing {startItem} to {endItem} of {totalItems} items
      </div>

      <div className="pagination-controls">
        <nav aria-label="Pagination">
          <ul className="pagination">
            <li className={`page-item ${currentPage === 1 ? 'disabled' : ''}`}>
              <button
                className="page-link"
                onClick={handlePrevious}
                disabled={currentPage === 1}
                aria-label="Previous page"
              >
                <i className="bi bi-chevron-left"></i>
                <span className="ms-1">Previous</span>
              </button>
            </li>

            {getPageNumbers().map((page, index) => (
              <li
                key={index}
                className={`page-item ${page === currentPage ? 'active' : ''} ${
                  page === '...' ? 'disabled' : ''
                }`}
              >
                {page === '...' ? (
                  <span className="page-link page-ellipsis">...</span>
                ) : (
                  <button
                    className="page-link"
                    onClick={() => onPageChange(page as number)}
                    aria-label={`Go to page ${page}`}
                    aria-current={page === currentPage ? 'page' : undefined}
                  >
                    {page}
                  </button>
                )}
              </li>
            ))}

            <li className={`page-item ${currentPage === totalPages ? 'disabled' : ''}`}>
              <button
                className="page-link"
                onClick={handleNext}
                disabled={currentPage === totalPages}
                aria-label="Next page"
              >
                <span className="me-1">Next</span>
                <i className="bi bi-chevron-right"></i>
              </button>
            </li>
          </ul>
        </nav>

        {showPageSizeSelector && onPageSizeChange && (
          <div className="page-size-selector">
            <label htmlFor="pageSize" className="form-label">
              Items per page:
            </label>
            <select
              id="pageSize"
              className="form-select"
              value={pageSize}
              onChange={handlePageSizeChange}
            >
              {pageSizeOptions.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>
    </div>
  )
}
