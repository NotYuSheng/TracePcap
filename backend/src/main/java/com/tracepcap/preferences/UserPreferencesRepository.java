package com.tracepcap.preferences;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserPreferencesRepository extends JpaRepository<UserPreferencesEntity, String> {}
