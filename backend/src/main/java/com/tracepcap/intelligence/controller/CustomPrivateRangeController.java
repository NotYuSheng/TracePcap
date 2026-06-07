package com.tracepcap.intelligence.controller;

import com.tracepcap.intelligence.dto.CustomPrivateRangeDto;
import com.tracepcap.intelligence.service.CustomPrivateRangeService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/custom-private-ranges")
@RequiredArgsConstructor
public class CustomPrivateRangeController {

  private final CustomPrivateRangeService service;

  @GetMapping
  public List<CustomPrivateRangeDto> list() {
    return service.list();
  }

  @PostMapping
  public ResponseEntity<?> create(@RequestBody CustomPrivateRangeDto dto) {
    if (dto.getCidr() == null || dto.getCidr().isBlank()) {
      return ResponseEntity.badRequest().body("IP address or CIDR is required");
    }
    try {
      return ResponseEntity.ok(service.create(dto));
    } catch (DataIntegrityViolationException e) {
      return ResponseEntity.badRequest().body("This CIDR is already in the list");
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    service.delete(id);
    return ResponseEntity.noContent().build();
  }
}
