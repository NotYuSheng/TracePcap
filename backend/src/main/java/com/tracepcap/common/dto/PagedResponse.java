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

  /** Create a paged response from a list and pagination parameters */
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
