package com.tracepcap.knowledge.controller;

import com.tracepcap.knowledge.dto.InvestigationCategoryResponse;
import com.tracepcap.knowledge.service.CategoryCatalogue;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** The investigation framework's categories (docs/architecture/investigation-framework.rst). */
@RestController
@RequestMapping("/investigation-categories")
@RequiredArgsConstructor
@Tag(
    name = "Investigation categories",
    description =
        "The fixed set of things an investigation can say something about: capture context, host"
            + " roles and the ATT&CK tactics, with the questions that answer each")
public class InvestigationCategoryController {

  private final CategoryCatalogue catalogue;

  @GetMapping
  @Operation(
      summary = "Every investigation category, with the questions that answer it",
      description =
          "Context, entities, then the 14 ATT&CK tactics, in that order. A category no question"
              + " covers yet is listed with none. Each carries how much of it a capture can show"
              + " and the traffic its questions read.")
  public ResponseEntity<List<InvestigationCategoryResponse>> listInvestigationCategories() {
    return ResponseEntity.ok(
        catalogue.entries().stream().map(InvestigationCategoryResponse::from).toList());
  }
}
