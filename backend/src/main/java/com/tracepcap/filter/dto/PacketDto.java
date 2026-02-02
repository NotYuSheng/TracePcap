package com.tracepcap.filter.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

/** DTO for a packet in filter results */
@Data
@Builder
public class PacketDto {

  private String id;

  private Long timestamp;

  private NetworkEndpoint source;

  private NetworkEndpoint destination;

  private Protocol protocol;

  private Integer size;

  private String payload;

  private List<String> flags;

  @Data
  @Builder
  public static class NetworkEndpoint {
    private String ip;
    private Integer port;
    private String mac;
    private String hostname;
  }

  @Data
  @Builder
  public static class Protocol {
    private String layer;
    private String name;
    private String version;
  }
}
