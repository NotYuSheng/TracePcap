package com.tracepcap.common.net;

/**
 * An address and port written for people (#1357): {@code 10.0.0.1:443}, and IPv6 in brackets,
 * {@code [fd00::1]:443}, since {@code fd00::1:443} reads as one address. The frontend's {@code
 * formatIpPort}. Not for keys: a flow key keeps whatever form its readers split on.
 */
public final class Endpoints {

  private Endpoints() {}

  /** {@code ip:port}, {@code [ip]:port} for IPv6, or {@code ip} alone when there is no port. */
  public static String of(String ip, Object port) {
    if (port == null) return ip;
    return (ip != null && ip.indexOf(':') >= 0 ? "[" + ip + "]" : ip) + ":" + port;
  }
}
