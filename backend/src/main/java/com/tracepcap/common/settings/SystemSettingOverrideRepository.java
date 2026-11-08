package com.tracepcap.common.settings;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SystemSettingOverrideRepository
    extends JpaRepository<SystemSettingOverrideEntity, String> {}
