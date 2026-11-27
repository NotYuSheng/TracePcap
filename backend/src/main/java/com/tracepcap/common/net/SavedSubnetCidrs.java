package com.tracepcap.common.net;

import java.util.Set;
import java.util.UUID;

/**
 * The subnet-label CIDRs a network sees, exactly as stored: the shared default's and its own. A
 * snapshot's subnet overrides are matched to these by text, so a label sent for one is kept in
 * that spelling ({@link Cidr#asSaved}), including a row V86 left as saved. A port so monitor can
 * ask without depending on subnets, which already depends on monitor.
 */
public interface SavedSubnetCidrs {

  Set<String> forNetwork(UUID networkId);
}
