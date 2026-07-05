package com.tracepcap.intelligence.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.intelligence.entity.CustomPrivateRangeEntity;
import com.tracepcap.intelligence.entity.IpClassification;
import com.tracepcap.intelligence.service.CustomPrivateRangeService.Override;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CustomPrivateRangeService#overrideFor}. It drives
 * {@code ChangeDetectionService.isPrivate}, so a bad match flips classification across the pipeline.
 * The method does not touch the repository, so a null repository is sufficient here.
 */
class CustomPrivateRangeServiceTest {

  private final CustomPrivateRangeService service = new CustomPrivateRangeService(null);

  private static CustomPrivateRangeEntity range(String cidr, IpClassification classification) {
    return CustomPrivateRangeEntity.builder().cidr(cidr).classification(classification).build();
  }

  @Test
  void overrideFor_publicRange_forcesPublic() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("10.0.0.0/8", IpClassification.PUBLIC));
    assertThat(service.overrideFor("10.1.2.3", ranges)).isEqualTo(Override.FORCE_PUBLIC);
  }

  @Test
  void overrideFor_privateRange_forcesPrivate() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("203.0.113.0/24", IpClassification.PRIVATE));
    assertThat(service.overrideFor("203.0.113.7", ranges)).isEqualTo(Override.FORCE_PRIVATE);
  }

  @Test
  void overrideFor_noMatch_returnsNone() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("10.0.0.0/8", IpClassification.PUBLIC));
    assertThat(service.overrideFor("192.168.1.1", ranges)).isEqualTo(Override.NONE);
  }

  @Test
  void overrideFor_overlappingRanges_firstMatchWins() {
    // Ranges arrive most-recent-first; the first matching entry should win regardless of the second.
    List<CustomPrivateRangeEntity> ranges =
        List.of(
            range("10.1.0.0/16", IpClassification.PUBLIC),
            range("10.0.0.0/8", IpClassification.PRIVATE));
    assertThat(service.overrideFor("10.1.2.3", ranges)).isEqualTo(Override.FORCE_PUBLIC);
  }

  @Test
  void overrideFor_nullIp_returnsNone() {
    List<CustomPrivateRangeEntity> ranges = List.of(range("10.0.0.0/8", IpClassification.PUBLIC));
    assertThat(service.overrideFor(null, ranges)).isEqualTo(Override.NONE);
  }

  @Test
  void overrideFor_nullOrEmptyRanges_returnsNone() {
    assertThat(service.overrideFor("10.1.2.3", null)).isEqualTo(Override.NONE);
    assertThat(service.overrideFor("10.1.2.3", List.of())).isEqualTo(Override.NONE);
  }
}
