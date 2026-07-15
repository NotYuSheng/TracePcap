package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.ExtractionRunEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExtractionRunRepository extends JpaRepository<ExtractionRunEntity, Long> {

  Optional<ExtractionRunEntity> findByFileIdAndExtractor(UUID fileId, String extractor);
}
