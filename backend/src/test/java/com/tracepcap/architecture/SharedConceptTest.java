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
   * The bare RFC rules are a default for contexts built without a policy (tests), not something to
   * pick in production code.
   */
  @ArchTest
  static final ArchRule rfc_only_rules_are_only_a_default =
      ArchRuleDefinition.noClasses()
          .that()
          .resideOutsideOfPackages("com.tracepcap.common.net..")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.knowledge.spi.KnowledgeContext")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.story.spi.ScanContext")
          .and()
          .doNotHaveFullyQualifiedName("com.tracepcap.story.service.LazyScanContext")
          .should()
          .accessField(LocalityRules.class, "RFC_ONLY")
          .because("production code takes LocalityRules from the policy, custom ranges included"
              + " (#1338)");
}
