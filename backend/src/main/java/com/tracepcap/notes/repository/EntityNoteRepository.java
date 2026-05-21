package com.tracepcap.notes.repository;

import com.tracepcap.notes.entity.EntityNoteEntity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EntityNoteRepository extends JpaRepository<EntityNoteEntity, Long> {

  Optional<EntityNoteEntity> findByEntityTypeAndEntityKey(String entityType, String entityKey);

  void deleteByEntityTypeAndEntityKey(String entityType, String entityKey);

  List<EntityNoteEntity> findByEntityKeyIn(Collection<String> entityKeys);
}
