package com.tracepcap.intelligence.controller;

import com.tracepcap.intelligence.dto.IpOrgRuleDto;
import com.tracepcap.intelligence.service.IpOrgRuleService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ip-org-rules")
@RequiredArgsConstructor
public class IpOrgRuleController {

  private final IpOrgRuleService service;

  @GetMapping
  public List<IpOrgRuleDto> list() {
    return service.list();
  }

  @PostMapping
  public ResponseEntity<?> create(@RequestBody IpOrgRuleDto dto) {
    if (dto.getLabel() == null || dto.getLabel().isBlank()) {
      return ResponseEntity.badRequest().body("Label is required");
    }
    if (dto.getCidr() == null || dto.getCidr().isBlank()) {
      return ResponseEntity.badRequest().body("CIDR is required");
    }
    try {
      return ResponseEntity.ok(service.create(dto));
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
