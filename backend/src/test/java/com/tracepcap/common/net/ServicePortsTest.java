package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * The one list of "ordinary infrastructure service port", shared by the knowledge-layer
 * BeaconContributor and the Story beacon detector (#823) so the two cannot disagree.
 */
class ServicePortsTest {

  @Test
  void recognisesWindowsAndDirectoryServicePorts() {
    for (int port : new int[] {139, 445, 88, 389, 636, 53, 443, 135}) { // NetBIOS/SMB/Kerberos/LDAP/DNS/TLS/RPC
      assertThat(ServicePorts.isInfrastructure(port)).as("port %d", port).isTrue();
    }
  }

  @Test
  void aHighEphemeralOrC2PortIsNotInfrastructure() {
    for (int port : new int[] {12132, 7777, 49754, 1337}) {
      assertThat(ServicePorts.isInfrastructure(port)).as("port %d", port).isFalse();
    }
  }

  @Test
  void nullPortIsNotInfrastructure() {
    assertThat(ServicePorts.isInfrastructure(null)).isFalse();
  }
}
