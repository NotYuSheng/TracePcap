package com.tracepcap.intelligence.repository;

import com.tracepcap.intelligence.entity.CustomPrivateRangeEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomPrivateRangeRepository extends JpaRepository<CustomPrivateRangeEntity, Long> {
  List<CustomPrivateRangeEntity> findAllByOrderByCreatedAtDesc();
}
