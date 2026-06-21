package com.tracepcap.intelligence.controller;

import com.tracepcap.intelligence.dto.IpOrgRuleDto;
import com.tracepcap.intelligence.service.IpOrgRuleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ip-org-rules")
@RequiredArgsConstructor
@Tag(name = "IP Org Rules", description = "User-defined CIDR-to-organization label mappings")
public class IpOrgRuleController {

  private final IpOrgRuleService service;

  @GetMapping
  @Operation(summary = "List IP organization rules")
  public List<IpOrgRuleDto> list() {
    return service.list();
  }

  @PostMapping
  @Operation(summary = "Add an IP organization rule")
  public ResponseEntity<?> create(@RequestBody IpOrgRuleDto dto) {
    if (dto.getLabel() == null || dto.getLabel().isBlank()) {
      return ResponseEntity.badRequest().body("Label is required");
    }
    if (dto.getCidr() == null || dto.getCidr().isBlank()) {
      return ResponseEntity.badRequest().body("CIDR is required");
    }
    try {
      return ResponseEntity.status(HttpStatus.CREATED).body(service.create(dto));
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  @DeleteMapping("/{id}")
  @Operation(summary = "Delete an IP organization rule")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    service.delete(id);
    return ResponseEntity.noContent().build();
  }
}
