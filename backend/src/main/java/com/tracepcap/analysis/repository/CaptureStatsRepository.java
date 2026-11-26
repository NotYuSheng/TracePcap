package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.CaptureStatsEntity;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CaptureStatsRepository extends JpaRepository<CaptureStatsEntity, UUID> {}
