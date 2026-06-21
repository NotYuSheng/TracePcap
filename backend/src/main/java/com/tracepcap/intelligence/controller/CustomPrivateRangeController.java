package com.tracepcap.intelligence.controller;

import com.tracepcap.intelligence.dto.CustomPrivateRangeDto;
import com.tracepcap.intelligence.service.CustomPrivateRangeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/custom-private-ranges")
@RequiredArgsConstructor
@Tag(
    name = "Custom Private Ranges",
    description = "User-defined CIDR ranges treated as private/internal")
public class CustomPrivateRangeController {

  private final CustomPrivateRangeService service;

  @GetMapping
  @Operation(summary = "List custom private ranges")
  public List<CustomPrivateRangeDto> list() {
    return service.list();
  }

  @PostMapping
  @Operation(summary = "Add a custom private range")
  public ResponseEntity<?> create(@RequestBody CustomPrivateRangeDto dto) {
    if (dto.getCidr() == null || dto.getCidr().isBlank()) {
      return ResponseEntity.badRequest().body("IP address or CIDR is required");
    }
    try {
      return ResponseEntity.status(HttpStatus.CREATED).body(service.create(dto));
    } catch (DataIntegrityViolationException e) {
      return ResponseEntity.badRequest().body("This CIDR is already in the list");
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  @DeleteMapping("/{id}")
  @Operation(summary = "Delete a custom private range")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    service.delete(id);
    return ResponseEntity.noContent().build();
  }
}
