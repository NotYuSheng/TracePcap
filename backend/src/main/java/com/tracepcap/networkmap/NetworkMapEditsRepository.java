package com.tracepcap.networkmap;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NetworkMapEditsRepository extends JpaRepository<NetworkMapEditsEntity, UUID> {}
