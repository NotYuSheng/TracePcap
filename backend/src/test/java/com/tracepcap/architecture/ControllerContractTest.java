package com.tracepcap.architecture;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaParameterizedType;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Enforces the REST conventions in {@code CLAUDE.md} across every controller at once.
 *
 * <p><b>These rules are green, not frozen</b> — unlike {@link LayerDependencyTest}. The codebase
 * already satisfies them, so they block from the first run and there is no violation store to
 * shrink. That is the whole point: 29 controllers had no test of any kind, and the conventions were
 * enforced only by whoever happened to review the PR.
 *
 * <p>One file covers all 29 controllers <em>and every controller anyone adds later</em>, which is
 * why this comes before per-controller {@code @WebMvcTest} slices (#659).
 *
 * <p>The version-prefix rule is the backend half of the defect in #630: the frontend built {@code
 * /api/files/...} while every route actually lives under {@code /api/v1}. The prefix is applied
 * centrally in {@code WebConfig.configurePathMatch}, so a controller that hard-codes it would be
 * served at {@code /api/v1/api/v1/...} — silently unreachable.
 */
@AnalyzeClasses(
    packages = "com.tracepcap",
    importOptions = {ImportOption.DoNotIncludeTests.class})
class ControllerContractTest {

  private static final List<Class<? extends java.lang.annotation.Annotation>> MAPPINGS =
      List.of(
          GetMapping.class,
          PostMapping.class,
          PutMapping.class,
          PatchMapping.class,
          DeleteMapping.class);

  /**
   * Lowercase segments, hyphen-separated, plus {@code {pathVariables}}. Rejects camelCase,
   * snake_case and stray uppercase — {@code /nodeRoles} instead of {@code /node-roles}.
   */
  private static final Pattern KEBAB_PATH =
      Pattern.compile("(/(\\{[A-Za-z][A-Za-z0-9]*}|[a-z0-9]+(-[a-z0-9]+)*))+");

  private static final DescribedPredicate<JavaClass> REST_CONTROLLERS =
      new DescribedPredicate<>("REST controllers") {
        @Override
        public boolean test(JavaClass javaClass) {
          return javaClass.isAnnotatedWith(RestController.class);
        }
      };

  /**
   * Controllers declare version-agnostic paths; {@code WebConfig.API_PREFIX} supplies {@code
   * /api/v1} centrally. Hard-coding it here double-prefixes the route.
   */
  @ArchTest
  static final ArchRule controllers_declare_version_agnostic_paths =
      ArchRuleDefinition.classes()
          .that(REST_CONTROLLERS)
          .should(
              new ArchCondition<>("not hard-code the /api or version prefix") {
                @Override
                public void check(JavaClass item, ConditionEvents events) {
                  for (String path : requestMappingPaths(item)) {
                    if (path.startsWith("/api") || path.matches("/v[0-9]+(/.*)?")) {
                      events.add(
                          SimpleConditionEvent.violated(
                              item,
                              item.getName()
                                  + " maps \""
                                  + path
                                  + "\": the /api/v1 prefix is applied centrally in WebConfig,"
                                  + " so this route would be served at /api/v1"
                                  + path));
                    }
                  }
                }
              });

  /** Resource paths are lowercase kebab-case (CLAUDE.md: plural kebab-case nouns). */
  @ArchTest
  static final ArchRule controller_paths_are_kebab_case =
      ArchRuleDefinition.classes()
          .that(REST_CONTROLLERS)
          .should(
              new ArchCondition<>("use kebab-case resource paths") {
                @Override
                public void check(JavaClass item, ConditionEvents events) {
                  for (String path : requestMappingPaths(item)) {
                    if (!path.isEmpty() && !KEBAB_PATH.matcher(path).matches()) {
                      events.add(
                          SimpleConditionEvent.violated(
                              item,
                              item.getName()
                                  + " maps \""
                                  + path
                                  + "\": resource paths are lowercase kebab-case"
                                  + " (/node-roles, not /nodeRoles)"));
                    }
                  }
                }
              });

  /** Every controller carries an OpenAPI {@code @Tag}; Swagger UI groups by it. */
  @ArchTest
  static final ArchRule controllers_are_tagged_for_openapi =
      ArchRuleDefinition.classes()
          .that(REST_CONTROLLERS)
          .should()
          .beAnnotatedWith(Tag.class)
          .because("every controller has a @Tag (CLAUDE.md API conventions)");

  /** Every handler method carries an {@code @Operation}, so the generated spec documents it. */
  @ArchTest
  static final ArchRule handler_methods_document_an_operation =
      ArchRuleDefinition.classes()
          .that(REST_CONTROLLERS)
          .should(
              new ArchCondition<>("annotate every handler method with @Operation") {
                @Override
                public void check(JavaClass item, ConditionEvents events) {
                  for (JavaMethod method : item.getMethods()) {
                    if (isHandler(method) && !method.isAnnotatedWith(Operation.class)) {
                      events.add(
                          SimpleConditionEvent.violated(
                              item,
                              method.getFullName()
                                  + " is a request handler without @Operation:"
                                  + " it would be undocumented in the OpenAPI spec,"
                                  + " which openapi/baseline.json snapshots"));
                    }
                  }
                }
              });

  /**
   * Controllers return DTOs, never JPA entities.
   *
   * <p>Returning an entity leaks the schema into the API: every column rename becomes a breaking
   * contract change, and lazy associations serialise unpredictably. Checks the type arguments of
   * {@code ResponseEntity<T>} as well as the bare return type — nested enums declared on an entity
   * (e.g. {@code FileEntity.FileSource}) are fine as query parameters and are not flagged, because
   * only the returned type is inspected.
   */
  @ArchTest
  static final ArchRule controllers_return_dtos_not_entities =
      ArchRuleDefinition.classes()
          .that(REST_CONTROLLERS)
          .should(
              new ArchCondition<>("not return JPA entities") {
                @Override
                public void check(JavaClass item, ConditionEvents events) {
                  for (JavaMethod method : item.getMethods()) {
                    if (!isHandler(method)) {
                      continue;
                    }
                    for (JavaClass returned : returnedTypes(method)) {
                      if (returned.getPackageName().endsWith(".entity")) {
                        events.add(
                            SimpleConditionEvent.violated(
                                item,
                                method.getFullName()
                                    + " returns "
                                    + returned.getName()
                                    + ": controllers return DTOs, so a column rename does not"
                                    + " become a breaking API change"));
                      }
                    }
                  }
                }
              });

  // --- helpers ---------------------------------------------------------------

  private static boolean isHandler(JavaMethod method) {
    return MAPPINGS.stream().anyMatch(method::isAnnotatedWith);
  }

  /** The paths declared on the class-level {@code @RequestMapping}, or empty when absent. */
  private static List<String> requestMappingPaths(JavaClass javaClass) {
    if (!javaClass.isAnnotatedWith(RequestMapping.class)) {
      return List.of();
    }
    RequestMapping mapping = javaClass.getAnnotationOfType(RequestMapping.class);
    List<String> declared =
        mapping.value().length > 0 ? List.of(mapping.value()) : List.of(mapping.path());
    return declared.stream().filter(p -> !p.isEmpty()).toList();
  }

  /**
   * The concrete types a handler can serialise: the raw return type, plus the type arguments of a
   * generic wrapper such as {@code ResponseEntity<PagedResponse<FileMetadataDto>>} (recursively, so
   * the DTO inside a nested wrapper is reached).
   */
  private static List<JavaClass> returnedTypes(JavaMethod method) {
    return flatten(method.getReturnType());
  }

  private static List<JavaClass> flatten(JavaType type) {
    JavaClass raw = type.toErasure();
    if (!(type instanceof JavaParameterizedType parameterized)) {
      return List.of(raw);
    }
    return java.util.stream.Stream.concat(
            java.util.stream.Stream.of(raw),
            parameterized.getActualTypeArguments().stream().flatMap(t -> flatten(t).stream()))
        .toList();
  }
}
