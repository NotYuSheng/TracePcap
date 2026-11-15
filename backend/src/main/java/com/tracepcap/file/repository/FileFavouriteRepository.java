package com.tracepcap.file.repository;

import com.tracepcap.file.entity.FileFavouriteEntity;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FileFavouriteRepository
    extends JpaRepository<FileFavouriteEntity, FileFavouriteEntity.Key> {

  @Query("SELECT f.fileId FROM FileFavouriteEntity f WHERE f.profileKey = :profile")
  Set<UUID> fileIdsFor(@Param("profile") String profileKey);
}
