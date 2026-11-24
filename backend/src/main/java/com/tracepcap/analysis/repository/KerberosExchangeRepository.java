package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.KerberosExchangeEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface KerberosExchangeRepository extends JpaRepository<KerberosExchangeEntity, UUID> {

  List<KerberosExchangeEntity> findByFileIdOrderByFirstTimeAsc(UUID fileId);

  @Modifying
  @Query("DELETE FROM KerberosExchangeEntity k WHERE k.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
