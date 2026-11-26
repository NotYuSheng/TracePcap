package com.tracepcap.knowledge.service;

import static com.tracepcap.knowledge.spi.EvidenceSource.DCERPC;
import static com.tracepcap.knowledge.spi.EvidenceSource.DHCP;
import static com.tracepcap.knowledge.spi.EvidenceSource.DNS;
import static com.tracepcap.knowledge.spi.EvidenceSource.FTP;
import static com.tracepcap.knowledge.spi.EvidenceSource.HTTP;
import static com.tracepcap.knowledge.spi.EvidenceSource.KERBEROS;
import static com.tracepcap.knowledge.spi.EvidenceSource.LDAP;
import static com.tracepcap.knowledge.spi.EvidenceSource.LOCAL_NAMES;
import static com.tracepcap.knowledge.spi.EvidenceSource.MAIL;
import static com.tracepcap.knowledge.spi.EvidenceSource.NETBIOS;
import static com.tracepcap.knowledge.spi.EvidenceSource.NTLM;
import static com.tracepcap.knowledge.spi.EvidenceSource.RDP;
import static com.tracepcap.knowledge.spi.EvidenceSource.REMOTE_CONTROL;
import static com.tracepcap.knowledge.spi.EvidenceSource.SMB;
import static com.tracepcap.knowledge.spi.EvidenceSource.TLS;

import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.spi.EvidenceSource;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Where to look for each category (#1292's "Worth a look", moved here from the frontend): the
 * protocols that speak to it and what they show there. Unlike a question's {@code requires()},
 * a lead is a pointer for a person, not a precondition: DNS is worth a look for a C2 even though the
 * C2 check reads alerts on any traffic.
 */
final class CategoryLeads {

  private CategoryLeads() {}

  private static final Map<Category, List<EvidenceSource>> LEADS = new EnumMap<>(Category.class);

  static {
    LEADS.put(Category.VICTIM, List.of(
        DHCP.showing("the hostname and MAC a device asked for its address with"),
        NETBIOS.showing("Windows machine names and workgroups"),
        LOCAL_NAMES.showing("names a machine announces or asks for on the local network")));
    LEADS.put(Category.SIGNED_IN_USER, List.of(
        KERBEROS.showing("the account a host asked the domain controller for a ticket as"),
        LDAP.showing("directory lookups, which name the person behind an account"),
        NTLM.showing("sign-ins by account name where Kerberos wasn’t used")));
    List<EvidenceSource> c2 = List.of(
        DNS.showing("every name a host looked up, a C2’s domain included"),
        TLS.showing("server names, certificates and JA3/JA4 fingerprints, even though the content"
            + " is encrypted"),
        HTTP.showing("URLs and user agents: check-ins and payload requests in the clear"));
    LEADS.put(Category.C2_SERVER, c2);
    LEADS.put(Category.COMMAND_AND_CONTROL, c2);
    LEADS.put(Category.REMOTE_ACCESS_SERVER, List.of(
        REMOTE_CONTROL.showing("someone controlling a machine from elsewhere")));
    LEADS.put(Category.INITIAL_ACCESS, List.of(
        HTTP.showing("files fetched in the clear, hashed in the Files tab"),
        FTP.showing("files moved over FTP")));
    LEADS.put(Category.DEFENSE_EVASION, List.of(
        DNS.showing("lookups to check for tunnelling or generated names")));
    LEADS.put(Category.CREDENTIAL_ACCESS, List.of(
        KERBEROS.showing("failed sign-ins by account, and each ticket’s encryption"),
        NTLM.showing("sign-in attempts by account name")));
    LEADS.put(Category.DISCOVERY, List.of(
        LDAP.showing("directory queries listing users, groups and computers"),
        SMB.showing("shares listed and browsed")));
    LEADS.put(Category.LATERAL_MOVEMENT, List.of(
        SMB.showing("shares connected to, admin shares, files copied to another machine"),
        DCERPC.showing("remote calls: services created, tasks scheduled, directory replication"),
        RDP.showing("interactive sessions on another machine")));
    LEADS.put(Category.EXFILTRATION, List.of(
        MAIL.showing("mail sent and fetched, attachments included"),
        FTP.showing("files sent out over FTP")));
  }

  /** The leads for one category, empty when there are none. */
  static List<EvidenceSource> of(Category c) {
    return LEADS.getOrDefault(c, List.of());
  }
}
