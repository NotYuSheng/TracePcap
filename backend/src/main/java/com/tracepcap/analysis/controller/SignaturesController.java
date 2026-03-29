package com.tracepcap.analysis.controller;

import io.swagger.v3.oas.annotations.Operation;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/** REST controller for reading and saving the custom signatures file. */
@Slf4j
@RestController
@RequestMapping("/api/signatures")
public class SignaturesController {

  @Value("${tracepcap.signatures.path:/app/config/signatures.yml}")
  private String signaturesPath;

  /** Returns the raw YAML content of the signatures file. */
  @GetMapping
  @Operation(summary = "Get custom signatures file content")
  public ResponseEntity<Map<String, String>> getSignatures() {
    File file = new File(signaturesPath);
    String content = "";
    if (file.exists()) {
      try {
        content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
      } catch (IOException e) {
        log.warn("Could not read signatures file: {}", e.getMessage());
      }
    }
    return ResponseEntity.ok(Map.of("content", content));
  }

  /** Returns parsed rule metadata (name + severity) for all configured signatures. */
  @GetMapping("/rules")
  @Operation(summary = "List configured signature rules with severity")
  @SuppressWarnings("unchecked")
  public ResponseEntity<List<Map<String, String>>> getSignatureRules() {
    File file = new File(signaturesPath);
    if (!file.exists()) return ResponseEntity.ok(List.of());
    try (FileInputStream fis = new FileInputStream(file)) {
      Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
      Map<String, Object> root = yaml.load(fis);
      if (root == null) return ResponseEntity.ok(List.of());
      Object raw = root.get("signatures");
      if (!(raw instanceof List)) return ResponseEntity.ok(List.of());
      List<Map<String, String>> result = new ArrayList<>();
      for (Object item : (List<?>) raw) {
        if (!(item instanceof Map)) continue;
        Map<String, Object> rule = (Map<String, Object>) item;
        String name = rule.get("name") != null ? rule.get("name").toString() : null;
        String severity = rule.get("severity") != null ? rule.get("severity").toString() : "low";
        if (name != null && !name.isBlank()) result.add(Map.of("name", name, "severity", severity));
      }
      return ResponseEntity.ok(result);
    } catch (Exception e) {
      log.warn("Could not parse signatures for rules endpoint: {}", e.getMessage());
      return ResponseEntity.ok(List.of());
    }
  }

  /** Validates and saves new YAML content to the signatures file. */
  @PutMapping
  @Operation(summary = "Save custom signatures file content")
  public ResponseEntity<Map<String, String>> saveSignatures(@RequestBody Map<String, String> body) {
    String content = body.getOrDefault("content", "");

    // Validate it's parseable YAML before writing
    try {
      Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
      yaml.load(content);
    } catch (Exception e) {
      return ResponseEntity.badRequest().body(Map.of("error", "Invalid YAML: " + e.getMessage()));
    }

    try {
      File file = new File(signaturesPath);
      Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
      log.info("Signatures file updated at {}", signaturesPath);
      return ResponseEntity.ok(Map.of("status", "saved"));
    } catch (IOException e) {
      log.error("Failed to write signatures file: {}", e.getMessage());
      return ResponseEntity.internalServerError()
          .body(Map.of("error", "Failed to save: " + e.getMessage()));
    }
  }
}
