package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.AnalysisResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AnalysisResultRepository extends JpaRepository<AnalysisResultEntity, UUID> {
    Optional<AnalysisResultEntity> findByFileId(UUID fileId);
    boolean existsByFileId(UUID fileId);
}
