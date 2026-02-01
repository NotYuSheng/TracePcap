package com.tracepcap.story.repository;

import com.tracepcap.story.entity.StoryEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository for Story entities
 */
@Repository
public interface StoryRepository extends JpaRepository<StoryEntity, UUID> {

    /**
     * Find the latest story for a file
     *
     * @param fileId the file ID
     * @return optional story entity
     */
    Optional<StoryEntity> findFirstByFileIdOrderByGeneratedAtDesc(UUID fileId);
}
