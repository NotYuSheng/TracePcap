package com.tracepcap.insights.dto;

/**
 * An LLM-generated role suggestion (label + description) for a node, not yet persisted (#369). Used
 * to pre-fill the "Update label" editor when re-classifying a drifted/stale label.
 */
public record RoleSuggestionDto(String roleLabel, String roleDescription) {}
