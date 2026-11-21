package com.tracepcap.governance;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.config.security.CurrentActor;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Who has signed in, for Settings › Users. Read-only in TracePcap: people, groups and role
 * assignments live in Keycloak. A sign-in is recorded when the app loads ({@code GET /me}), at most
 * every few minutes per person unless their roles changed.
 */
@Service
@RequiredArgsConstructor
public class UserDirectoryService {

  static final int MAX_PAGE_SIZE = 200;
  /** How often one person's sign-in is written again when nothing about it changed. */
  static final Duration REFRESH = Duration.ofMinutes(5);

  private final SignedInUserRepository repository;
  private final RoleRepository roleRepository;
  private final CurrentActor currentActor;

  /** Subject → when it was last written and with which roles, to skip needless writes. */
  private final Map<String, Recent> recent = new ConcurrentHashMap<>();

  private record Recent(LocalDateTime at, Set<String> roles) {}

  /** Records the caller's sign-in. Nothing with login off, or for a caller without an account. */
  @Transactional
  public void recordCaller() {
    if (!currentActor.authEnabled()) return;
    String subject = currentActor.subject();
    if (subject == null) return;
    Set<String> roles = new TreeSet<>(currentActor.roles());
    LocalDateTime now = LocalDateTime.now();
    Recent last = recent.get(subject);
    if (last != null && last.roles().equals(roles) && last.at().plus(REFRESH).isAfter(now)) return;

    SignedInUserEntity user = repository.findById(subject).orElseGet(
        () -> SignedInUserEntity.builder().subject(subject).firstSeen(now).build());
    user.setUsername(currentActor.username());
    user.setDisplayName(currentActor.displayName());
    user.setClientRoles(roles.toArray(String[]::new));
    user.setLastSeen(now);
    repository.save(user);
    recent.put(subject, new Recent(now, roles));
  }

  /** Everyone who has signed in, newest first; {@code search} matches username or name. */
  @Transactional(readOnly = true)
  public PagedResponse<UserDto> list(int page, int pageSize, String search) {
    if (page < 1) throw new IllegalArgumentException("page must be 1 or more");
    if (pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
      throw new IllegalArgumentException("pageSize must be between 1 and " + MAX_PAGE_SIZE);
    }
    String q =
        search == null || search.isBlank()
            ? null
            : "%" + search.trim().toLowerCase(Locale.ROOT).replace("%", "\\%").replace("_", "\\_") + "%";
    Page<SignedInUserEntity> result = repository.search(q, PageRequest.of(page - 1, pageSize));
    List<RoleEntity> roles = roleRepository.findAllByOrderByPositionDescKeyAsc();
    Map<String, RoleEntity> byKey = roles.stream().collect(Collectors.toMap(RoleEntity::getKey, Function.identity()));
    RoleEntity fallback = roles.stream().filter(RoleEntity::isDefaultRole).findFirst().orElse(null);
    return PagedResponse.of(
        result.getContent().stream().map(u -> toDto(u, roles, byKey, fallback)).toList(),
        result.getTotalElements(),
        page,
        pageSize);
  }

  /** When a sign-in last carried {@code roleKey}, or null if none has. */
  @Transactional(readOnly = true)
  public LocalDateTime lastSignInWith(String roleKey) {
    return repository.lastSeenWithRole(roleKey);
  }

  private static UserDto toDto(
      SignedInUserEntity u, List<RoleEntity> roles, Map<String, RoleEntity> byKey, RoleEntity fallback) {
    Set<String> carried = new TreeSet<>(Arrays.asList(u.getClientRoles() == null ? new String[0] : u.getClientRoles()));
    List<RoleEntity> mine = roles.stream().filter(r -> carried.contains(r.getKey())).toList();
    boolean usesDefault = mine.isEmpty() && fallback != null;
    List<RoleEntity> effective = usesDefault ? List.of(fallback) : mine;
    return UserDto.builder()
        .username(u.getUsername())
        .displayName(u.getDisplayName())
        .roles(effective.stream().map(RoleEntity::getKey).toList())
        .defaultRole(usesDefault)
        .unknownRoles(carried.stream().filter(k -> !byKey.containsKey(k)).toList())
        .permissionCount(PermissionService.permissionsOf(effective).size())
        .firstSeen(u.getFirstSeen())
        .lastSeen(u.getLastSeen())
        .build();
  }
}
