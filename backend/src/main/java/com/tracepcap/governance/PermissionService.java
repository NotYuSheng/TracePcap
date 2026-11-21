package com.tracepcap.governance;

import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Decides what the caller may do, from their roles, and lets an admin change what each role may do.
 *
 * <p><b>Whose roles.</b> Login on: the TracePcap roles among the Keycloak client roles in the
 * caller's token ({@link CurrentActor#roles()}); someone whose token carries none of them gets the
 * default role. Login off: there are no accounts, so everyone has every role but admin, as before
 * roles existed (everything open except admin-only items), and admin too when {@code
 * SYSTEM_SETTINGS_EDITABLE=true}.
 *
 * <p><b>What they may do.</b> Everything any of their roles allows. The admin role always has every
 * permission, so no one can lock the admins out from inside TracePcap. Everyone may see captures;
 * only admins may change roles.
 */
@Service
@RequiredArgsConstructor
public class PermissionService {

  static final String AUDIT_TARGET = "role";

  /** What a role key (a Keycloak client role name) may look like. */
  public static final String ROLE_KEY_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._-]*$";

  /** Custom roles list after the built-in ones (Settings lists the highest position first). */
  static final int CUSTOM_ROLE_POSITION = 0;

  private final RoleRepository roleRepository;
  private final CurrentActor currentActor;
  private final AuditLogService auditLog;

  /** The roles that apply to the caller, in the order Settings lists them. */
  @Transactional(readOnly = true)
  public List<RoleEntity> callerRoles() {
    List<RoleEntity> all = roleRepository.findAllByOrderByPositionDescKeyAsc();
    if (!currentActor.authEnabled()) {
      boolean admin = currentActor.isAdmin();
      return all.stream().filter(r -> admin || !isAdminRole(r)).toList();
    }
    Set<String> fromToken = currentActor.roles();
    List<RoleEntity> mine = all.stream().filter(r -> fromToken.contains(r.getKey())).toList();
    if (!mine.isEmpty()) return mine;
    return all.stream().filter(RoleEntity::isDefaultRole).toList();
  }

  /** Every permission the caller has. */
  @Transactional(readOnly = true)
  public Set<PermissionAction> callerPermissions() {
    return permissionsOf(callerRoles());
  }

  @Transactional(readOnly = true)
  public boolean can(PermissionAction action) {
    return callerPermissions().contains(action);
  }

  /** Throws a 403 with the reason unless the caller may perform {@code action}. */
  @Transactional(readOnly = true)
  public void require(PermissionAction action) {
    if (!can(action)) throw new ForbiddenException(action.label() + ": " + reasonFor(action));
  }

  /** Why the caller may not perform {@code action}, or null when they may. */
  @Transactional(readOnly = true)
  public String reason(PermissionAction action) {
    return can(action) ? null : reasonFor(action);
  }

  /**
   * Deleting a capture: the caller's own needs {@link PermissionAction#DELETE_OWN_CAPTURES}, anyone
   * else's (or one with no recorded uploader) {@link PermissionAction#DELETE_ANY_CAPTURES}.
   */
  @Transactional(readOnly = true)
  public void requireDeleteCapture(String uploadedBy) {
    Set<PermissionAction> mine = callerPermissions();
    if (mine.contains(PermissionAction.DELETE_ANY_CAPTURES)) return;
    boolean own = uploadedBy != null && uploadedBy.equals(currentActor.username());
    if (own) {
      require(PermissionAction.DELETE_OWN_CAPTURES);
      return;
    }
    throw new ForbiddenException(
        PermissionAction.DELETE_ANY_CAPTURES.label()
            + ": "
            + (uploadedBy == null
                ? "this capture has no recorded uploader, so deleting it needs a role that may delete"
                    + " anyone's captures."
                : "it was uploaded by " + uploadedBy + ". " + reasonFor(PermissionAction.DELETE_ANY_CAPTURES)));
  }

  /** The whole catalogue, as it applies to the caller. */
  @Transactional(readOnly = true)
  public List<PermissionDto> list() {
    Set<PermissionAction> mine = callerPermissions();
    return Arrays.stream(PermissionAction.values())
        .map(a -> toDto(a, mine.contains(a)))
        .toList();
  }

  /** Whether the caller may change roles. Only the admin role may. */
  public boolean canManage() {
    return currentActor.isAdmin();
  }

  /** Why the caller can't change roles, or null when they can. */
  public String manageReason() {
    return canManage() ? null : reasonFor(PermissionAction.MANAGE_ROLES);
  }

  /** Every role and what it may do. */
  @Transactional(readOnly = true)
  public List<RoleDto> listRoles() {
    return roleRepository.findAllByOrderByPositionDescKeyAsc().stream().map(this::toDto).toList();
  }

  /**
   * Sets what a role may do. Admin only, audited. The admin role can't be changed (it always has
   * everything); everyone keeps {@link PermissionAction#SEE_CAPTURES}; {@link
   * PermissionAction#MANAGE_ROLES} stays the admin role's alone.
   */
  @Transactional
  public RoleDto setPermissions(String key, Set<PermissionAction> requested) {
    requireManage();
    RoleEntity role = find(key);
    if (isAdminRole(role)) {
      throw new IllegalArgumentException("The admin role always has every permission and can't be changed.");
    }
    Set<String> next = requested.stream()
        .filter(a -> !a.fixed())
        .map(Enum::name)
        .collect(Collectors.toCollection(TreeSet::new));
    next.add(PermissionAction.SEE_CAPTURES.name());
    Set<String> before = new TreeSet<>(role.getPermissions());
    if (!before.equals(next)) {
      role.getPermissions().clear();
      role.getPermissions().addAll(next);
      touch(role);
      roleRepository.save(role);
      auditLog.record(
          "role.permissions.update", AUDIT_TARGET, key, Map.of("permissions", before), Map.of("permissions", next));
    }
    return toDto(role);
  }

  /** Makes {@code key} the role for someone whose sign-in carries none. Admin only, audited. */
  @Transactional
  public RoleDto setDefault(String key) {
    requireManage();
    RoleEntity role = find(key);
    if (isAdminRole(role)) {
      throw new IllegalArgumentException(
          "The admin role can't be the default: everyone who signs in would be an admin.");
    }
    RoleEntity before = roleRepository.findFirstByDefaultRoleTrue().orElse(null);
    if (before != null && before.getKey().equals(key)) return toDto(role);
    if (before != null) {
      before.setDefaultRole(false);
      touch(before);
      roleRepository.saveAndFlush(before);
    }
    role.setDefaultRole(true);
    touch(role);
    roleRepository.save(role);
    Map<String, Object> was = new LinkedHashMap<>();
    was.put("defaultRole", before == null ? null : before.getKey());
    auditLog.record("role.default.set", AUDIT_TARGET, key, was, Map.of("defaultRole", key));
    return toDto(role);
  }

  /**
   * Creates a custom role, optionally starting from another role's permissions. Admin only,
   * audited. Who has it is still decided in Keycloak, by the client role named {@code key}.
   */
  @Transactional
  public RoleDto createRole(String key, String label, String description, String copyFrom) {
    requireManage();
    String k = key == null ? "" : key.trim();
    if (!k.matches(ROLE_KEY_PATTERN) || k.length() > 100) {
      throw new IllegalArgumentException(
          "A role's Keycloak name may use letters, digits, '-', '_' and '.', starting with a letter or digit.");
    }
    if (roleRepository.existsById(k)) {
      throw new IllegalArgumentException("There is already a role named " + k + ".");
    }
    String name = label == null ? "" : label.trim();
    if (name.isEmpty()) throw new IllegalArgumentException("A role needs a name.");
    Set<String> perms = new TreeSet<>();
    if (copyFrom != null && !copyFrom.isBlank()) {
      RoleEntity source = find(copyFrom);
      // The admin role's stored set is empty: copying it means everything a role can hold.
      if (isAdminRole(source)) {
        Arrays.stream(PermissionAction.values()).filter(a -> !a.fixed()).forEach(a -> perms.add(a.name()));
      } else {
        source.getPermissions().stream().filter(n -> parse(n) != null && !parse(n).fixed()).forEach(perms::add);
      }
    }
    perms.add(PermissionAction.SEE_CAPTURES.name());
    RoleEntity role = RoleEntity.builder()
        .key(k)
        .label(name)
        .description(blankToNull(description))
        .builtIn(false)
        .position(CUSTOM_ROLE_POSITION)
        .defaultRole(false)
        .permissions(perms)
        .build();
    touch(role);
    roleRepository.save(role);
    Map<String, Object> after = new LinkedHashMap<>();
    after.put("label", role.getLabel());
    after.put("description", role.getDescription());
    after.put("copyFrom", blankToNull(copyFrom));
    after.put("permissions", perms);
    auditLog.record("role.create", AUDIT_TARGET, k, null, after);
    return toDto(role);
  }

  /** Renames a custom role or changes its description. Admin only, audited. */
  @Transactional
  public RoleDto setDetails(String key, String label, String description) {
    requireManage();
    RoleEntity role = find(key);
    if (role.isBuiltIn()) {
      throw new IllegalArgumentException("Built-in roles keep their name and description.");
    }
    Map<String, Object> before = new LinkedHashMap<>();
    before.put("label", role.getLabel());
    before.put("description", role.getDescription());
    if (label != null) {
      if (label.isBlank()) throw new IllegalArgumentException("A role needs a name.");
      role.setLabel(label.trim());
    }
    if (description != null) role.setDescription(blankToNull(description));
    Map<String, Object> after = new LinkedHashMap<>();
    after.put("label", role.getLabel());
    after.put("description", role.getDescription());
    if (!before.equals(after)) {
      touch(role);
      roleRepository.save(role);
      auditLog.record("role.update", AUDIT_TARGET, key, before, after);
    }
    return toDto(role);
  }

  /**
   * Deletes a custom role. Admin only, audited. Built-in roles and the default role can't be
   * deleted. Anyone Keycloak still gives the client role simply stops getting anything from it.
   */
  @Transactional
  public void deleteRole(String key) {
    requireManage();
    RoleEntity role = find(key);
    if (role.isBuiltIn()) throw new IllegalArgumentException("Built-in roles can't be deleted.");
    if (role.isDefaultRole()) {
      throw new IllegalArgumentException(
          "This is the default role. Make another role the default before deleting it.");
    }
    Map<String, Object> before = new LinkedHashMap<>();
    before.put("label", role.getLabel());
    before.put("description", role.getDescription());
    before.put("permissions", new TreeSet<>(role.getPermissions()));
    roleRepository.delete(role);
    auditLog.record("role.delete", AUDIT_TARGET, key, before, null);
  }

  private static String blankToNull(String s) {
    return s == null || s.isBlank() ? null : s.trim();
  }

  private Set<PermissionAction> permissionsOf(List<RoleEntity> roles) {
    if (roles.stream().anyMatch(this::isAdminRole)) return EnumSet.allOf(PermissionAction.class);
    Set<PermissionAction> out = EnumSet.of(PermissionAction.SEE_CAPTURES);
    for (RoleEntity role : roles) {
      for (String name : role.getPermissions()) {
        PermissionAction action = parse(name);
        if (action != null && action != PermissionAction.MANAGE_ROLES) out.add(action);
      }
    }
    return out;
  }

  private boolean isAdminRole(RoleEntity role) {
    return BuiltInRole.ADMIN.key().equals(role.getKey());
  }

  private void requireManage() {
    if (!canManage()) throw new ForbiddenException("Changing roles: " + manageReason());
  }

  private RoleEntity find(String key) {
    return roleRepository.findById(key).orElseThrow(() -> new ResourceNotFoundException("Role", "key", key));
  }

  private void touch(RoleEntity role) {
    role.setUpdatedAt(LocalDateTime.now());
    role.setUpdatedBy(currentActor.username());
  }

  private static PermissionAction parse(String name) {
    try {
      return PermissionAction.valueOf(name);
    } catch (IllegalArgumentException retired) {
      return null; // a permission a later version removed: it gives nothing
    }
  }

  private String reasonFor(PermissionAction action) {
    if (action == PermissionAction.MANAGE_ROLES) {
      return currentActor.authEnabled()
          ? "only the admin role can change this. Ask an admin, or for the admin role in Keycloak."
          : "only admins can change this, and with login off that needs SYSTEM_SETTINGS_EDITABLE=true on the server.";
    }
    if (!currentActor.authEnabled()) {
      return "only admins can change this, and with login off that needs SYSTEM_SETTINGS_EDITABLE=true on"
          + " the server.";
    }
    String names = callerRoles().stream().map(RoleEntity::getLabel).collect(Collectors.joining(", "));
    return "your role" + (names.contains(",") ? "s (" : " (") + names
        + ") doesn't include this. Ask an admin to add it to your role, or for a role in Keycloak that has it.";
  }

  private PermissionDto toDto(PermissionAction a, boolean allowed) {
    return PermissionDto.builder()
        .action(a)
        .label(a.label())
        .description(a.description())
        .group(a.group())
        .groupLabel(a.group().label())
        .suggestedRole(a.lowest().key())
        .fixed(a.fixed())
        .allowed(allowed)
        .reason(allowed ? null : reasonFor(a))
        .build();
  }

  private RoleDto toDto(RoleEntity role) {
    boolean admin = isAdminRole(role);
    List<PermissionAction> perms = admin
        ? List.of(PermissionAction.values())
        : Arrays.stream(PermissionAction.values())
            .filter(a -> a == PermissionAction.SEE_CAPTURES || role.getPermissions().contains(a.name()))
            .filter(a -> a != PermissionAction.MANAGE_ROLES)
            .toList();
    return RoleDto.builder()
        .key(role.getKey())
        .label(role.getLabel())
        .description(role.getDescription())
        .builtIn(role.isBuiltIn())
        .defaultRole(role.isDefaultRole())
        .editable(!admin)
        .permissions(perms)
        .build();
  }
}
