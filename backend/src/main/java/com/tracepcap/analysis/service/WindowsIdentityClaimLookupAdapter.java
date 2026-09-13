package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.WindowsIdentityClaimEntity;
import com.tracepcap.analysis.repository.WindowsIdentityClaimRepository;
import com.tracepcap.analysis.spi.WindowsIdentityClaimLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link WindowsIdentityClaimLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class WindowsIdentityClaimLookupAdapter implements WindowsIdentityClaimLookup {

  private final WindowsIdentityClaimRepository repository;

  @Override
  public List<UsernameClaim> claimsForFile(UUID fileId) {
    return repository.findByFileId(fileId).stream().map(this::toClaim).toList();
  }

  private UsernameClaim toClaim(WindowsIdentityClaimEntity e) {
    return new UsernameClaim(e.getIp(), e.getUsername(), e.getSource());
  }
}
