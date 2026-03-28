package com.tracepcap.common.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Generic paginated response wrapper */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PagedResponse<T> {
  private List<T> data;
  private int page;
  private int pageSize;
  private long total;
  private int totalPages;

  /**
   * Create a paged response when DB has already done filtering/pagination.
   * The content list is used as-is; total comes from the DB count.
   */
  public static <T> PagedResponse<T> of(List<T> content, long total, int page, int pageSize) {
    int totalPages = pageSize > 0 ? (int) Math.ceil((double) total / pageSize) : 0;
    return PagedResponse.<T>builder()
        .data(content)
        .page(page)
        .pageSize(pageSize)
        .total(total)
        .totalPages(totalPages)
        .build();
  }

  /** Create a paged response from a full in-memory list (slices it here). */
  public static <T> PagedResponse<T> of(List<T> allData, int page, int pageSize) {
    long total = allData.size();
    int totalPages = (int) Math.ceil((double) total / pageSize);

    // Calculate start and end indices for the current page
    int startIndex = (page - 1) * pageSize;
    int endIndex = Math.min(startIndex + pageSize, allData.size());

    // Extract the data for the current page
    List<T> pageData =
        startIndex < allData.size() ? allData.subList(startIndex, endIndex) : List.of();

    return PagedResponse.<T>builder()
        .data(pageData)
        .page(page)
        .pageSize(pageSize)
        .total(total)
        .totalPages(totalPages)
        .build();
  }
}
