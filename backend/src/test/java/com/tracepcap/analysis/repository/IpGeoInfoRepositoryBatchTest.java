package com.tracepcap.analysis.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class IpGeoInfoRepositoryBatchTest {

  @Test
  void aScanCapturesAddressesAreLookedUpABatchAtATime() {
    IpGeoInfoRepository repo = mock(IpGeoInfoRepository.class, CALLS_REAL_METHODS);
    List<Integer> sizes = new ArrayList<>();
    when(repo.findAllByIpIn(anyCollection())).thenAnswer(inv -> {
      Collection<String> ips = inv.getArgument(0);
      sizes.add(ips.size());
      return ips.stream().map(ip -> { var e = new IpGeoInfoEntity(); e.setIp(ip); return e; }).toList();
    });
    List<String> ips = IntStream.range(0, 12_001).mapToObj(i -> "198.18." + (i >> 8) + "." + (i & 255)).toList();

    List<IpGeoInfoEntity> found = repo.findByIps(ips);

    assertThat(found).hasSize(12_001);
    assertThat(sizes).containsExactly(5_000, 5_000, 2_001);
    assertThat(repo.findByIps(List.of())).isEmpty();
  }
}
