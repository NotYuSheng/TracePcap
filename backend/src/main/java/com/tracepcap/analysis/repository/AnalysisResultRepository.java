package com.lanturn.analysis.repository;

import com.lanturn.analysis.entity.AnalysisResultEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AnalysisResultRepository extends JpaRepository<AnalysisResultEntity, UUID> {
  Optional<AnalysisResultEntity> findByFileId(UUID fileId);

  boolean existsByFileId(UUID fileId);
}
