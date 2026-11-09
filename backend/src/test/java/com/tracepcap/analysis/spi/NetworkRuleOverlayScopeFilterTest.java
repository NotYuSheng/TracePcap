package com.tracepcap.analysis.spi;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The one rule for filtering by detection rule in a network's view (#925). */
class NetworkRuleOverlayScopeFilterTest {

  private static final UUID NET = UUID.randomUUID();
  private static final UUID FILE = UUID.randomUUID();
  private static final UUID CONV = UUID.randomUUID();

  private final NetworkRuleOverlay overlay =
      new NetworkRuleOverlay() {
        public Map<UUID, List<String>> labels(UUID n, UUID f) { return Map.of(); }
        public Set<UUID> conversationsMatching(UUID n, UUID f, Collection<String> names) {
          return names.contains("net-rule") ? Set.of(CONV) : Set.of();
        }
        public Set<String> suppressedNames(UUID n) { return Set.of("noisy-global"); }
        public Map<UUID, Set<String>> matchedNamesByFile(UUID n, Collection<UUID> f) { return Map.of(); }
      };

  @Test
  void noNetworkOrNoRuleFilterIsUnchanged() {
    var p = ConversationFilterParams.builder().customSignatures(List.of("x")).build();
    assertThat(overlay.scopeFilter(null, FILE, p)).isSameAs(p);
    var none = ConversationFilterParams.builder().build();
    assertThat(overlay.scopeFilter(NET, FILE, none)).isSameAs(none);
  }

  @Test
  void suppressedNamesDropOut_andNetworkMatchesComeByConversationId() {
    var p = ConversationFilterParams.builder().customSignatures(List.of("noisy-global", "net-rule", "kept")).build();
    var scoped = overlay.scopeFilter(NET, FILE, p);
    assertThat(scoped.getCustomSignatures()).containsExactly("net-rule", "kept");
    assertThat(scoped.getCustomSignatureMatchIds()).containsExactly(CONV);
  }

  @Test
  void onlySuppressedNamesMatchNothingByName() {
    var p = ConversationFilterParams.builder().customSignatures(List.of("noisy-global")).build();
    assertThat(overlay.scopeFilter(NET, FILE, p).getCustomSignatures()).containsExactly("");
  }
}
