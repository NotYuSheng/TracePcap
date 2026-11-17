package com.tracepcap.story.repository;

import com.tracepcap.story.entity.StoryEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** Repository for Story entities */
@Repository
public interface StoryRepository extends JpaRepository<StoryEntity, UUID> {

  /**
   * Find the latest story for a file
   *
   * @param fileId the file ID
   * @return optional story entity
   */
  /** The newest story of this status: a failed regenerate doesn't hide the last good story. */
  Optional<StoryEntity> findFirstByFileIdAndStatusOrderByGeneratedAtDesc(
      UUID fileId, StoryEntity.StoryStatus status);

  @Transactional
  void deleteByFileId(UUID fileId);
}
