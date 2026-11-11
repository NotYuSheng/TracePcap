package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.service.HostnameResolverService;
import com.tracepcap.analysis.service.PcapParserService;
import com.tracepcap.analysis.service.WindowsIdentityResolverService;
import com.tracepcap.file.entity.FileEntity;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Port for classifying hosts (device type / role) from observed traffic during the analysis
 * pipeline.
 *
 * <p>Defined in {@code analysis} (the ingest core) and implemented by the {@code hostclassification}
 * feature module, so the pipeline depends on this abstraction rather than on the concrete
 * classification engine. Returns the core {@link HostClassificationEntity} records, which the
 * pipeline post-processes (e.g. service-log suspicions) and persists.
 */
public interface HostClassifier {

  List<HostClassificationEntity> classify(ClassificationRequest request);

  /**
   * A host's whole score board (#925): points and reasons per device type, and the detection
   * rules' votes counted in them. Kept so a rule change can be re-scored without the inputs.
   */
  record Board(Map<String, Integer> scores, Map<String, List<String>> reasons, List<ClassificationHint> ruleVotes) {}

  /** A re-scored verdict, and the board it came from. */
  record Verdict(
      String deviceType,
      int confidence,
      Integer winnerScore,
      String runnerUpType,
      Integer runnerUpScore,
      String winnerReasons,
      String runnerUpReasons,
      Board board) {}

  /**
   * Re-scores a stored board with the detection rules' current votes (#925): the old rule votes
   * are taken back and {@code votes} counted, then the winner, confidence and runner-up are worked
   * out again. Empty when the votes are the same as before.
   */
  java.util.Optional<Verdict> rescoreRuleVotes(Board stored, List<ClassificationHint> votes);

  /**
   * Everything one classification run reads (#421), replacing an 8-argument call whose
   * same-typed maps were easy to pass in the wrong order.
   *
   * <p>A null collection becomes an empty one rather than an exception. That's no stricter than
   * the old signature, which every caller already filled with non-null values, and it makes "this
   * input has nothing" impossible to confuse with a missing argument. {@code file} stays as given.
   *
   * @param conversations parsed conversations; the host profiles are built from these
   * @param hostTtls observed IP TTL per host
   * @param hostMacs source MAC per host IP
   * @param ruleHints detection rules' weighted device-type votes, by IP (#926)
   * @param hostnames adjudicated hostname per IP
   * @param serviceRolesByIp service-log roles per IP (dns, web, api, tls...)
   * @param windowsIdentityClaimsByIp Kerberos / LDAP sign-in claims per IP (#809)
   */
  record ClassificationRequest(
      FileEntity file,
      List<PcapParserService.ConversationInfo> conversations,
      Map<String, Integer> hostTtls,
      Map<String, String> hostMacs,
      Map<String, List<ClassificationHint>> ruleHints,
      Map<String, HostnameResolverService.ResolvedHostname> hostnames,
      Map<String, Set<String>> serviceRolesByIp,
      Map<String, List<WindowsIdentityResolverService.Claim>> windowsIdentityClaimsByIp,
      Map<String, Board> boardsOut) {

    /** Without a board sink: the boards (#925) aren't kept. */
    public ClassificationRequest(
        FileEntity file,
        List<PcapParserService.ConversationInfo> conversations,
        Map<String, Integer> hostTtls,
        Map<String, String> hostMacs,
        Map<String, List<ClassificationHint>> ruleHints,
        Map<String, HostnameResolverService.ResolvedHostname> hostnames,
        Map<String, Set<String>> serviceRolesByIp,
        Map<String, List<WindowsIdentityResolverService.Claim>> windowsIdentityClaimsByIp) {
      this(file, conversations, hostTtls, hostMacs, ruleHints, hostnames, serviceRolesByIp,
          windowsIdentityClaimsByIp, null);
    }

    public ClassificationRequest {
      // Filled by the classifier with each host's score board, by IP, when the caller passes a
      // map (#925); a fresh one otherwise, so the classifier never checks.
      boardsOut = boardsOut == null ? new java.util.HashMap<>() : boardsOut;
      conversations = conversations == null ? List.of() : conversations;
      hostTtls = hostTtls == null ? Map.of() : hostTtls;
      hostMacs = hostMacs == null ? Map.of() : hostMacs;
      ruleHints = ruleHints == null ? Map.of() : ruleHints;
      hostnames = hostnames == null ? Map.of() : hostnames;
      serviceRolesByIp = serviceRolesByIp == null ? Map.of() : serviceRolesByIp;
      windowsIdentityClaimsByIp =
          windowsIdentityClaimsByIp == null ? Map.of() : windowsIdentityClaimsByIp;
    }

    /** A request with only the conversations set, the rest empty. Tests start here. */
    public static ClassificationRequest of(
        FileEntity file, List<PcapParserService.ConversationInfo> conversations) {
      return new ClassificationRequest(file, conversations, null, null, null, null, null, null);
    }
  }
}
