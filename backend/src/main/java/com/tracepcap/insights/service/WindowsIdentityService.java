package com.tracepcap.insights.service;

import com.tracepcap.analysis.spi.WindowsIdentityClaimLookup;
import com.tracepcap.analysis.spi.WindowsIdentityClaimLookup.UsernameClaim;
import com.tracepcap.common.adjudication.HumanOverrideEntity;
import com.tracepcap.common.adjudication.HumanOverrideRepository;
import com.tracepcap.common.stage.Adjudicator;
import com.tracepcap.common.stage.Tier;
import com.tracepcap.insights.entity.WindowsIdentityEntity;
import com.tracepcap.insights.repository.WindowsIdentityRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The Windows-identity adjudicator (#809) — one voice for "who is logged into this host?",
 * answering the gap found via the #808 CTF demo: TracePcap could name the malware family and the
 * victim's IP/MAC/hostname unprompted, but not the person behind the keyboard.
 *
 * <p>Deliberately simpler than {@link HostIdentityService} (the "what is this host?" adjudicator it
 * sits alongside): there is no weighted vote across evidence axes or analyst-appended evidence
 * here, because there is no equivalent of "device-type classification signals" to combine — just
 * two claim sources with an inherent trust ordering.
 *
 * <ol>
 *   <li>A human override for this IP (question {@code "windows-identity"}) — basis HUMAN,
 *       confidence 100, never contested. The analyst has spoken.
 *   <li>Otherwise, source-priority over the claims {@link WindowsIdentityResolverService} recorded:
 *       a Kerberos AS-REQ claim is MEASURED (the client's own authentication request) and wins over
 *       an LDAP DN claim, which is REPORTED and ambiguous (see that class's doc). The losing
 *       source, when present, rides along in {@code candidates} as corroboration, not a competing
 *       vote — the two are not weighed against each other.
 *   <li>Multiple <em>distinct</em> usernames claimed by the same source tier for one IP (a shared
 *       kiosk, say) make the identity contested: no clear winner, all candidates listed.
 *   <li>An IP with no claims gets <b>no row at all</b> — unlike host identity, "nobody observed"
 *       is a legitimate empty state here, not a MISSING/UNKNOWN label to synthesize.
 * </ol>
 *
 * <p>Re-adjudication fires on analysis completion and on human-override changes (via {@code
 * AdjudicatorRunner}, which this class registers with by existing — no manual wiring). Rows are
 * versioned per run: delete-and-regenerate per file.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WindowsIdentityService implements Adjudicator {

  /** The adjudicated question this module answers — also the key its human overrides are filed under. */
  static final String QUESTION = "windows-identity";

  private static final int CONFIDENCE_HUMAN = 100;
  private static final int CONFIDENCE_KERBEROS = 90;
  private static final int CONFIDENCE_LDAP_ONLY = 55;
  private static final int CONFIDENCE_CONTESTED = 40;

  private final WindowsIdentityClaimLookup windowsIdentityClaimLookup;
  private final WindowsIdentityRepository windowsIdentityRepository;
  private final HumanOverrideRepository humanOverrideRepository;

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public Tier tier() {
    // Source-priority, not a language model or a trained classifier — arithmetic over which
    // protocol asserted what.
    return Tier.DETERMINISTIC;
  }

  @Override
  public void adjudicate(UUID fileId) {
    adjudicateFile(fileId);
  }

  @Transactional
  public void adjudicateFile(UUID fileId) {
    Map<String, HumanOverrideEntity> overrideByIp = new LinkedHashMap<>();
    for (HumanOverrideEntity o : humanOverrideRepository.findByQuestionAndFileId(QUESTION, fileId)) {
      overrideByIp.put(o.getEntityKey(), o);
    }

    Map<String, List<UsernameClaim>> claimsByIp = new LinkedHashMap<>();
    for (UsernameClaim claim : windowsIdentityClaimLookup.claimsForFile(fileId)) {
      claimsByIp.computeIfAbsent(claim.ip(), k -> new ArrayList<>()).add(claim);
    }

    // Every IP that has either an override or a claim gets a row; an IP with neither gets none.
    Set<String> ips = new LinkedHashSet<>();
    ips.addAll(overrideByIp.keySet());
    ips.addAll(claimsByIp.keySet());

    List<WindowsIdentityEntity> identities = new ArrayList<>(ips.size());
    int contestedCount = 0;
    for (String ip : ips) {
      HumanOverrideEntity override = overrideByIp.get(ip);
      List<UsernameClaim> claims = claimsByIp.getOrDefault(ip, List.of());
      WindowsIdentityEntity identity =
          override != null ? fromOverride(fileId, ip, override, claims) : fromClaims(fileId, ip, claims);
      if (identity == null) continue; // fromClaims returns null when there is nothing to say
      if (identity.isContested()) contestedCount++;
      identities.add(identity);
    }

    windowsIdentityRepository.deleteByFileId(fileId);
    windowsIdentityRepository.saveAll(identities);
    log.info(
        "Adjudicated {} Windows identit(ies) for file {} ({} contested, {} overridden)",
        identities.size(),
        fileId,
        contestedCount,
        overrideByIp.size());
  }

  /**
   * A human-decided identity: their label IS the answer (confidence 100, never contested), but the
   * machine's claims — if any exist for this IP — still ride along in {@code candidates} so the UI
   * can keep explaining what the claims said. Overriding the verdict must not erase the explanation
   * it overrode (same reasoning as {@code HostIdentityService.humanIdentity}).
   */
  private WindowsIdentityEntity fromOverride(
      UUID fileId, String ip, HumanOverrideEntity override, List<UsernameClaim> claims) {
    List<Map<String, Object>> candidates = new ArrayList<>();
    candidates.add(candidate(override.getLabel(), "human-override", CONFIDENCE_HUMAN));
    candidates.addAll(candidatesFromClaims(claims));
    return WindowsIdentityEntity.builder()
        .fileId(fileId)
        .ip(ip)
        .primaryLabel(override.getLabel())
        .basis(WindowsIdentityEntity.BASIS_HUMAN)
        .confidence(CONFIDENCE_HUMAN)
        .contested(false)
        .candidates(candidates)
        .updatedAt(LocalDateTime.now())
        .build();
  }

  /** Returns null when there are no claims for this IP — no row is emitted in that case. */
  private WindowsIdentityEntity fromClaims(UUID fileId, String ip, List<UsernameClaim> claims) {
    if (claims.isEmpty()) return null;

    Set<String> kerberosNames = namesForSource(claims, WindowsIdentityClaimLookup.SOURCE_KERBEROS_AS_REQ);
    Set<String> ldapNames = namesForSource(claims, WindowsIdentityClaimLookup.SOURCE_LDAP_DN);
    List<Map<String, Object>> candidates = candidatesFromClaims(claims);

    String primaryLabel;
    int confidence;
    boolean contested;

    if (kerberosNames.size() > 1) {
      // Multiple distinct authenticated principals for one IP (shared kiosk) — no clear winner.
      primaryLabel = String.join(" / ", kerberosNames);
      confidence = CONFIDENCE_CONTESTED;
      contested = true;
    } else if (kerberosNames.size() == 1) {
      // Kerberos wins outright over LDAP when present — MEASURED beats REPORTED. The LDAP claims
      // (if any) still ride along in candidates as corroboration, not as competing votes.
      primaryLabel = kerberosNames.iterator().next();
      confidence = CONFIDENCE_KERBEROS;
      contested = false;
    } else if (ldapNames.size() > 1) {
      primaryLabel = String.join(" / ", ldapNames);
      confidence = CONFIDENCE_CONTESTED;
      contested = true;
    } else {
      // Exactly one LDAP-only claim.
      primaryLabel = ldapNames.iterator().next();
      confidence = CONFIDENCE_LDAP_ONLY;
      contested = false;
    }

    return WindowsIdentityEntity.builder()
        .fileId(fileId)
        .ip(ip)
        .primaryLabel(primaryLabel)
        .basis(WindowsIdentityEntity.BASIS_MACHINE)
        .confidence(confidence)
        .contested(contested)
        .candidates(candidates)
        .updatedAt(LocalDateTime.now())
        .build();
  }

  private Set<String> namesForSource(List<UsernameClaim> claims, String source) {
    Set<String> names = new LinkedHashSet<>();
    for (UsernameClaim c : claims) {
      if (source.equals(c.source())) names.add(c.username());
    }
    return names;
  }

  /** Every distinct claim, Kerberos first (higher-confidence source), as display candidates. */
  private List<Map<String, Object>> candidatesFromClaims(List<UsernameClaim> claims) {
    List<Map<String, Object>> candidates = new ArrayList<>();
    for (String name : namesForSource(claims, WindowsIdentityClaimLookup.SOURCE_KERBEROS_AS_REQ)) {
      candidates.add(candidate(name, WindowsIdentityClaimLookup.SOURCE_KERBEROS_AS_REQ, CONFIDENCE_KERBEROS));
    }
    for (String name : namesForSource(claims, WindowsIdentityClaimLookup.SOURCE_LDAP_DN)) {
      candidates.add(candidate(name, WindowsIdentityClaimLookup.SOURCE_LDAP_DN, CONFIDENCE_LDAP_ONLY));
    }
    return candidates;
  }

  private Map<String, Object> candidate(String label, String source, int score) {
    return Map.of("label", label, "source", source, "score", score);
  }
}
