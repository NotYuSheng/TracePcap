package com.tracepcap.architecture;

import static com.tngtech.archunit.library.freeze.FreezingArchRule.freeze;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;

/**
 * Enforces the module boundaries described in {@code docs/architecture/layers.rst} (#512).
 *
 * <p><b>These rules are frozen, not green.</b> The codebase violates them today; freezing records
 * the current violations as an accepted baseline so the build fails only on <em>new</em> ones. Each
 * refactor slice deletes violations from the store. <b>The store must only ever shrink.</b>
 *
 * <p>This is the mechanism #416 lacked. That epic established "dependency direction is always
 * feature → analysis, never the reverse", and the rule eroded anyway — because nothing enforced it.
 *
 * <p>Violation stores live in {@code src/test/resources/archunit_store} (see
 * {@code archunit.properties}). To accept a deliberate new violation, run once with
 * {@code -Darchunit.freeze.store.default.allowStoreUpdate=true} and justify it in the PR.
 */
@AnalyzeClasses(
    packages = "com.tracepcap",
    importOptions = {ImportOption.DoNotIncludeTests.class})
class LayerDependencyTest {

  /**
   * Modules must consume {@code analysis} through its published seam — {@code analysis.spi} (ports),
   * {@code analysis.dto}, and the {@code public static} core types on {@code PcapParserService} —
   * never its repositories or JPA entities.
   *
   * <p>A repository import couples a module to how analysis stores data; an entity import couples it
   * to the schema. Both make the ingest pipeline unchangeable without touching every consumer, which
   * is the cost measured in #512: 71 such imports against a single use of the {@code spi} package
   * that exists precisely to prevent them.
   *
   * <p>{@code analysis}' own classes are exempt — the rule governs crossing the boundary, not
   * working inside it.
   */
  @ArchTest
  static final ArchRule modules_use_analysis_spi_not_its_internals =
      freeze(
          ArchRuleDefinition.noClasses()
              .that()
              .resideOutsideOfPackage("com.tracepcap.analysis..")
              .should()
              .dependOnClassesThat()
              .resideInAnyPackage(
                  "com.tracepcap.analysis.repository..", "com.tracepcap.analysis.entity..")
              .because(
                  "cross-module access to analysis must go through analysis.spi / analysis.dto"
                      + " (#512); reaching into repositories or entities pins the ingest pipeline"
                      + " in place"));

  /**
   * No dependency cycles between modules.
   *
   * <p>Two exist today:
   *
   * <ul>
   *   <li>{@code monitor ↔ insights} — each imports the other's repositories and entities. Note
   *       {@code monitor → insights} already uses an event ({@code NodeRoleChangedEvent}), so the
   *       decoupling pattern is present and simply not applied consistently.
   *   <li>{@code analysis ↔ file} — {@code file} needs only {@code AsyncAnalysisService}: a single
   *       narrow edge, and the natural first candidate for an event or a port.
   * </ul>
   *
   * <p>A cycle means neither module can be understood, tested, or extracted on its own.
   */
  @ArchTest
  static final ArchRule no_module_cycles =
      freeze(
          SlicesRuleDefinition.slices()
              .matching("com.tracepcap.(*)..")
              .namingSlices("$1")
              .should()
              .beFreeOfCycles());

  /**
   * The layering direction #416 established: the ingest pipeline owns ports, feature modules
   * implement them. {@code analysis} must never depend on the modules above it.
   *
   * <p>This rule currently has <b>zero</b> violations — #416's core invariant held. It is frozen
   * anyway so a regression is reported as "analysis reached upward" rather than as an anonymous
   * slice violation, and so the store documents that this boundary is clean.
   */
  @ArchTest
  static final ArchRule analysis_does_not_depend_on_feature_modules =
      freeze(
          ArchRuleDefinition.noClasses()
              .that()
              .resideInAPackage("com.tracepcap.analysis..")
              .should()
              .dependOnClassesThat()
              .resideInAnyPackage(
                  "com.tracepcap.monitor..",
                  "com.tracepcap.story..",
                  "com.tracepcap.insights..",
                  "com.tracepcap.intelligence..",
                  "com.tracepcap.subnets..",
                  "com.tracepcap.report..",
                  "com.tracepcap.tracer..",
                  "com.tracepcap.filter..")
              .because(
                  "#416: dependency direction is always feature → analysis, never the reverse"));
}
