package com.tracepcap.file.service;

import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.file.entity.FileFavouriteEntity;
import com.tracepcap.file.repository.FileFavouriteRepository;
import com.tracepcap.file.repository.FileRepository;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The caller's favourite captures: personal, keyed by the same profile as their preferences (the
 * account when login is on, the one shared profile when it's off).
 */
@Service
@RequiredArgsConstructor
public class FileFavouriteService {

  private final FileFavouriteRepository favourites;
  private final FileRepository files;
  private final CurrentActor currentActor;

  @Transactional(readOnly = true)
  public Set<UUID> favouriteIds() {
    return favourites.fileIdsFor(currentActor.profileKey());
  }

  /** Marks a capture as a favourite. Idempotent: marking one twice keeps one row. */
  @Transactional
  public void add(UUID fileId) {
    if (!files.existsById(fileId)) throw new ResourceNotFoundException("File", "id", fileId);
    String profile = currentActor.profileKey();
    if (favourites.existsById(new FileFavouriteEntity.Key(profile, fileId))) return;
    favourites.save(new FileFavouriteEntity(profile, fileId, LocalDateTime.now()));
  }

  /** Unmarks it. Idempotent too. */
  @Transactional
  public void remove(UUID fileId) {
    favourites.deleteById(new FileFavouriteEntity.Key(currentActor.profileKey(), fileId));
  }
}
