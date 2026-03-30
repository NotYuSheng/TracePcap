import React from 'react';
import { Pagination as SgdsPagination } from '@govtechsg/sgds-react';
import './Pagination.css';

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  totalItems?: number;
  pageSize?: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  pageSizeOptions?: number[];
  showPageSizeSelector?: boolean;
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
  if (totalPages === 0) return null;

  const startItem = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(currentPage * pageSize, totalItems);

  // SGDS requires a React state setter; wrap our callback to be compatible
  const setCurrentPage: React.Dispatch<React.SetStateAction<number>> = value => {
    const newPage = typeof value === 'function' ? value(currentPage) : value;
    onPageChange(newPage);
  };

  const handlePageSizeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newPageSize = parseInt(e.target.value, 10);
    if (onPageSizeChange) {
      onPageSizeChange(newPageSize);
    }
  };

  return (
    <div className="pagination-container">
      <div className="pagination-meta">
        <span className="pagination-info">
          Showing {startItem} to {endItem} of {totalItems} items
        </span>

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
              {pageSizeOptions.map(size => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div
        onClickCapture={e => {
          const anchor = (e.target as HTMLElement).closest('a');
          if (anchor) e.preventDefault();
        }}
      >
        <SgdsPagination
          dataLength={totalItems}
          currentPage={currentPage}
          itemsPerPage={pageSize}
          setCurrentPage={setCurrentPage}
          size="sm"
          limit={5}
          ellipsisOn
          ellipsisJump={2}
          directionVariant="icon-text"
        />
      </div>
    </div>
  );
};
