package com.tracepcap.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.common.net.LocalityRules;

/**
 * Concepts with one definition must also have one way in (#1342). The Shared Vocabulary check
 * (#733) stops a concept's literals from being copied; it can't see a caller reaching past the
 * entry point to the bare definition, which is how the investigation answers came to ignore the
 * operator's custom ranges while the graph honoured them (#1338).
 *
 * <p>Not frozen: there are no violations to accept, and a new one should fail the build.
 */
@AnalyzeClasses(
    packages = "com.tracepcap",
    importOptions = {ImportOption.DoNotIncludeTests.class})
class SharedConceptTest {

  /**
   * "Is this address local" is asked of {@link LocalityRules}: from {@code KnowledgeContext}, {@code
   * ScanContext}, or {@code LocalityPolicy}. Only the policy layers custom ranges over the RFC
   * ranges, and GeoIP wants the bare RFC answer (a private address has no geography).
   */
  @ArchTest
  static final ArchRule locality_goes_through_the_policy =
      ArchRuleDefinition.noClasses()
          .that()
          .resideOutsideOfPackages("com.tracepcap.common.net..", "com.tracepcap.policy.service..")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.analysis.service.GeoIpService")
          .should()
          .callMethod(IpLocality.class, "isLocal", String.class)
          .because(
              "IpLocality.isLocal ignores the operator's custom ranges: ask LocalityRules from"
                  + " KnowledgeContext.locality(), ScanContext.locality() or LocalityPolicy (#1338)");

  /**
   * The bare RFC rules are the policy's answer when no range is configured, and a context's
   * fallback when the ranges can't be read; production code doesn't pick them itself.
   */
  @ArchTest
  static final ArchRule rfc_only_rules_are_only_a_default =
      ArchRuleDefinition.noClasses()
          .that()
          .resideOutsideOfPackages("com.tracepcap.common.net..", "com.tracepcap.policy.service..")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.knowledge.spi.KnowledgeContext")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.story.service.LazyScanContext")
          .should()
          .accessField(LocalityRules.class, "RFC_ONLY")
          .because("production code takes LocalityRules from the policy, custom ranges included"
              + " (#1338)");

  /**
   * An address string is read by {@code Cidr.addressBytes} and matched by {@code CidrBlock}
   * (#1354). {@code InetAddress.getByName} on anything that isn't a literal (a MAC endpoint, free
   * text) is a DNS lookup, which offline hangs until it times out, and five hand-rolled CIDR
   * matchers each guarded that differently, or not at all.
   */
  @ArchTest
  static final ArchRule addresses_are_read_by_cidr =
      ArchRuleDefinition.noClasses()
          .that()
          .resideOutsideOfPackage("com.tracepcap.common.net..")
          .should()
          .callMethod(java.net.InetAddress.class, "getByName", String.class)
          .orShould()
          .callMethod(java.net.InetAddress.class, "getAllByName", String.class)
          .because(
              "read an address with Cidr.addressBytes and match it with CidrBlock.contains: never a"
                  + " DNS lookup (#1354)");

  /**
   * A capture's networks are read by {@code NetworkSegmentReader} (#1357): from its DHCP leases and
   * its IPv6 router advertisements. Five readers each called {@code NetworkSegments.of} on the
   * leases alone, and any one left on that path would see a dual-stack VLAN without its IPv6 half.
   */
  @ArchTest
  static final ArchRule networks_are_read_whole =
      ArchRuleDefinition.noClasses()
          .that()
          .doNotHaveFullyQualifiedName("com.tracepcap.analysis.service.NetworkSegmentReader")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.analysis.service.NetworkSegments")
          .should()
          .callMethod(com.tracepcap.analysis.service.NetworkSegments.class, "of", java.util.List.class)
          .orShould()
          .callMethod(
              com.tracepcap.analysis.service.NetworkSegments.class, "of", java.util.List.class, java.util.List.class)
          .because("read a capture's networks with NetworkSegmentReader.of: leases and router adverts (#1357)");

  /**
   * The geo cache is read by address through {@code findByIps}, which batches: one IN with a scan
   * capture's 200k addresses ran the analysis out of heap and past Postgres's bind limit (#1374).
   */
  @ArchTest
  static final ArchRule geo_cache_is_read_in_batches =
      ArchRuleDefinition.noClasses()
          .that()
          .doNotHaveFullyQualifiedName("com.tracepcap.analysis.repository.IpGeoInfoRepository")
          .should()
          .callMethod(
              com.tracepcap.analysis.repository.IpGeoInfoRepository.class,
              "findAllByIpIn",
              java.util.Collection.class)
          .because("read the geo cache with findByIps, which batches the IN (#1374)");
}
