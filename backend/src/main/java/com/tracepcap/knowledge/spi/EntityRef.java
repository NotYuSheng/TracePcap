package com.tracepcap.knowledge.spi;

/**
 * A stable, comparable reference to an entity on the board — its {@link EntityType} plus a natural
 * key (an IP for a host, a username for a user). Two artifacts naming the same {@code (type, key)}
 * refer to the same node, which is how contributors that never call each other still agree on what
 * they are talking about.
 */
public record EntityRef(EntityType type, String key) {
  public EntityRef {
    if (type == null || key == null || key.isBlank()) {
      throw new IllegalArgumentException("EntityRef needs a type and a non-blank key");
    }
  }

  public static EntityRef host(String ip) {
    return new EntityRef(EntityType.HOST, ip);
  }

  public static EntityRef user(String username) {
    return new EntityRef(EntityType.USER, username);
  }

  public static EntityRef external(String ip) {
    return new EntityRef(EntityType.EXTERNAL_SERVICE, ip);
  }

  public static EntityRef malware(String family) {
    return new EntityRef(EntityType.MALWARE, family);
  }
}
