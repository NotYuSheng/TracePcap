package com.tracepcap.report;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import lombok.Data;
import lombok.NoArgsConstructor;

/** What to put in a capture's report, and the network map the browser drew for it. */
@Data
@NoArgsConstructor
public class ReportRequest {

  /** The report's parts after its summary page, in the order they print. */
  public enum Section {
    /** What needs a look, on the summary page. */
    NEEDS_A_LOOK,
    /** Hosts grouped by the network they're on, with names. */
    HOSTS,
    /** The grouped network map. */
    MAP,
    /** The Story tab's narrative and findings, when written. */
    STORY,
    /** Where the traffic goes, flows between organisations, protocols and apps. */
    TRAFFIC,
    /** The busiest conversations and the internet hosts. */
    CONVERSATIONS,
    /** Files carved from the capture, when extraction ran. */
    EXTRACTED_FILES,
    /** Every flagged conversation, and how each device was classified. */
    APPENDIX
  }

  /** The briefing: for someone who won't open TracePcap. */
  public static final Set<Section> BRIEFING =
      EnumSet.of(Section.NEEDS_A_LOOK, Section.HOSTS, Section.MAP, Section.STORY);

  /** Which parts to include; null or empty is the briefing. */
  private List<Section> sections;

  /** The network map as a base64 JPEG or PNG, drawn by the browser; null leaves the map out. */
  private String mapImage;

  /** What the map shows, e.g. "As you left it: Protocol: HTTPS · 120 of 430 hosts". */
  private String mapCaption;

  /**
   * The network the capture is viewed in (#925): its own detection rules' matches are included,
   * and the global rules it switches off are left out. Null for the shared rules only.
   */
  private java.util.UUID networkId;

  /** The sections asked for, or the briefing's. */
  public Set<Section> effectiveSections() {
    return sections == null || sections.isEmpty() ? EnumSet.copyOf(BRIEFING) : EnumSet.copyOf(sections);
  }
}
