package com.tracepcap.preferences;

import com.tracepcap.config.security.CurrentActor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads and writes the caller's personal preferences (#915 phase 2): the logged-in account's, or
 * the single shared profile when login is off.
 */
@Service
@RequiredArgsConstructor
public class PreferencesService {

  /** A node-label config is a few hundred bytes; this only stops abuse of the JSON column. */
  static final int MAX_NODE_LABEL_CONFIG_BYTES = 16 * 1024;

  private final UserPreferencesRepository repository;
  private final CurrentActor currentActor;
  private final ObjectMapper objectMapper;

  @Transactional(readOnly = true)
  public PreferencesDto get() {
    String profile = currentActor.profileKey();
    Map<String, Object> stored =
        repository.findById(profile).map(UserPreferencesEntity::getPreferences).orElse(Map.of());
    return toDto(stored, profile);
  }

  /** Replaces the caller's preferences. Fields left null go back to the app default. */
  @Transactional
  public PreferencesDto put(PreferencesDto dto) {
    String profile = currentActor.profileKey();
    if (dto.getNodeLabelConfig() != null) {
      try {
        if (objectMapper.writeValueAsBytes(dto.getNodeLabelConfig()).length > MAX_NODE_LABEL_CONFIG_BYTES) {
          throw new IllegalArgumentException("nodeLabelConfig is too large");
        }
      } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
        throw new IllegalArgumentException("nodeLabelConfig is not valid JSON");
      }
    }
    Map<String, Object> prefs = new LinkedHashMap<>();
    if (dto.getThemeMode() != null) prefs.put("themeMode", dto.getThemeMode());
    if (dto.getNodeLabelConfig() != null) prefs.put("nodeLabelConfig", dto.getNodeLabelConfig());
    if (dto.getConversationColumns() != null) prefs.put("conversationColumns", dto.getConversationColumns());
    repository.save(
        UserPreferencesEntity.builder()
            .profileKey(profile)
            .preferences(prefs)
            .updatedAt(LocalDateTime.now())
            .build());
    return toDto(prefs, profile);
  }

  @SuppressWarnings("unchecked")
  private static PreferencesDto toDto(Map<String, Object> p, String profile) {
    return PreferencesDto.builder()
        .themeMode((String) p.get("themeMode"))
        .nodeLabelConfig((Map<String, Object>) p.get("nodeLabelConfig"))
        .conversationColumns((List<String>) p.get("conversationColumns"))
        .shared(CurrentActor.SHARED_PROFILE.equals(profile))
        .build();
  }
}
