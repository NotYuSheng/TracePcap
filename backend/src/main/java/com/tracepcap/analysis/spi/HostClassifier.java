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
   * @param deviceOverrides device type forced by custom signatures, by IP
   * @param hostnames adjudicated hostname per IP
   * @param serviceRolesByIp service-log roles per IP (dns, web, api, tls...)
   * @param windowsIdentityClaimsByIp Kerberos / LDAP sign-in claims per IP (#809)
   */
  record ClassificationRequest(
      FileEntity file,
      List<PcapParserService.ConversationInfo> conversations,
      Map<String, Integer> hostTtls,
      Map<String, String> hostMacs,
      Map<String, String> deviceOverrides,
      Map<String, HostnameResolverService.ResolvedHostname> hostnames,
      Map<String, Set<String>> serviceRolesByIp,
      Map<String, List<WindowsIdentityResolverService.Claim>> windowsIdentityClaimsByIp) {

    public ClassificationRequest {
      conversations = conversations == null ? List.of() : conversations;
      hostTtls = hostTtls == null ? Map.of() : hostTtls;
      hostMacs = hostMacs == null ? Map.of() : hostMacs;
      deviceOverrides = deviceOverrides == null ? Map.of() : deviceOverrides;
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
