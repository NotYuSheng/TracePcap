package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.UUID;

/**
 * What each server in a capture said about itself: its banners, its SSH HASSH and the initial TTL
 * of its SYN-ACKs. <b>REPORTED</b>, except the TTL: a server chooses its banner, so a banner says
 * what the software claims to be, which is exactly what a honeypot fakes.
 */
public interface ServiceBannerLookup {

  /**
   * @param kind ssh-banner, ssh-hassh, ftp-banner, http-server, smb-os, smb-server-name,
   *     mysql-version or ttl (the initial TTL, 32, 64, 128 or 255, estimated from the observed one)
   * @param count how many times the server sent it on that port
   */
  record Banner(String ip, int port, String kind, String value, int count) {}

  List<Banner> banners(UUID fileId);

  /** What one server sent. */
  List<Banner> banners(UUID fileId, String ip);
}
