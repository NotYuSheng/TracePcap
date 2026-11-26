package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ServiceBannerLookup.Banner;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The banner pass over the honeypot gate capture (scripts/honeypot-capture.sh): the fixture is
 * tshark's own output for {@link ServiceBannerExtractor#FIELDS} on that capture.
 */
class ServiceBannerExtractorTest {

  private static final String COWRIE = "198.51.100.22";
  private static final String DIONAEA = "198.51.100.45";

  private static List<Banner> gate() throws IOException {
    ServiceBannerExtractor.Tally tally = new ServiceBannerExtractor.Tally();
    try (InputStream in = ServiceBannerExtractorTest.class.getResourceAsStream(
        "/honeypot/gate-banner-rows.tsv")) {
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        if (!line.isEmpty()) tally.accept(line.split("\t", -1));
      }
    }
    return tally.banners();
  }

  private static List<String> values(List<Banner> banners, String ip, String kind) {
    return banners.stream().filter(b -> b.ip().equals(ip) && b.kind().equals(kind))
        .map(Banner::value).distinct().toList();
  }

  @Test
  void readsEachServersOwnBanners() throws IOException {
    List<Banner> b = gate();
    assertThat(values(b, COWRIE, "ssh-banner")).containsExactly("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3");
    assertThat(values(b, COWRIE, "ssh-hassh")).containsExactly("6fa2f18e2061da02d6c8a9009674fa4e");
    assertThat(values(b, DIONAEA, "ftp-banner")).containsExactly("DiskStation FTP server ready.");
    assertThat(values(b, DIONAEA, "smb-server-name")).containsExactly("HOMEUSER-3AF6FE");
    assertThat(values(b, DIONAEA, "smb-os")).containsExactly("Windows 5.1 / Windows 2000 LAN Manager");
    assertThat(values(b, DIONAEA, "mysql-version")).containsExactly("5.7.16");
    assertThat(values(b, DIONAEA, "http-server")).containsExactly("nginx");
    assertThat(values(b, DIONAEA, "ttl")).containsExactly("64");
  }

  @Test
  void aClientsOwnBannerIsNotTheServers() throws IOException {
    List<Banner> b = gate();
    // The attackers sent "SSH-2.0-Go" and OpenSSH's client string: they're clients, not servers.
    assertThat(b).noneMatch(x -> x.ip().startsWith("198.51.100.10") && x.kind().equals("ssh-banner"));
    assertThat(b).noneMatch(x -> x.value().startsWith("SSH-2.0-Go"));
  }

  @Test
  void repeatsAreCountedOnOneRow() throws IOException {
    Banner ftp = gate().stream()
        .filter(x -> x.ip().equals(DIONAEA) && x.kind().equals("ftp-banner")).findFirst().orElseThrow();
    assertThat(ftp.port()).isEqualTo(21);
    assertThat(ftp.count()).isGreaterThan(1);
  }

  @Test
  void withoutAHandshakeTheLowerPortIsTheServer() {
    ServiceBannerExtractor.Tally tally = new ServiceBannerExtractor.Tally();
    String[] row = new String[ServiceBannerExtractor.FIELDS.length];
    java.util.Arrays.fill(row, "");
    row[0] = "10.0.0.5";
    row[2] = "22";
    row[3] = "51515";
    row[8] = "SSH-2.0-OpenSSH_8.9";
    tally.accept(row);
    String[] client = row.clone();
    client[0] = "10.0.0.9";
    client[2] = "51515";
    client[3] = "22";
    client[8] = "SSH-2.0-PuTTY";
    tally.accept(client);
    assertThat(tally.banners()).extracting(Banner::value).containsExactly("SSH-2.0-OpenSSH_8.9");
  }

  @Test
  void theInitialTtlIsEstimatedFromTheObservedOne() {
    assertThat(ServiceBannerExtractor.initialTtl(57)).isEqualTo(64);
    assertThat(ServiceBannerExtractor.initialTtl(64)).isEqualTo(64);
    assertThat(ServiceBannerExtractor.initialTtl(113)).isEqualTo(128);
    assertThat(ServiceBannerExtractor.initialTtl(240)).isEqualTo(255);
  }
}
