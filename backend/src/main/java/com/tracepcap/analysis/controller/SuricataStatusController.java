package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.SuricataStatusDto;
import com.tracepcap.analysis.service.SuricataRuleset;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/system/suricata")
@RequiredArgsConstructor
@Tag(name = "Suricata", description = "The IDS engine and the age of the ruleset behind its alerts")
public class SuricataStatusController {

  private final SuricataRuleset ruleset;

  @GetMapping
  @Operation(
      summary = "Which Suricata ruleset is in use, and how old it is",
      description =
          "source is built-in (baked into the image) or imported (from the import folder). stale is"
              + " true once the ruleset is older than SURICATA_RULESET_STALE_DAYS. importError says why"
              + " the last imported bundle wasn't used.")
  public SuricataStatusDto status() {
    SuricataRuleset.Status s = ruleset.status();
    return SuricataStatusDto.builder()
        .engineVersion(s.engineVersion())
        .source(s.source())
        .rulesetDate(s.rulesetDate())
        .ageDays(s.ageDays())
        .stale(s.stale())
        .staleAfterDays(s.staleAfterDays())
        .ruleCount(s.ruleCount())
        .importDir(s.importDir())
        .importError(s.importError())
        .build();
  }
}
