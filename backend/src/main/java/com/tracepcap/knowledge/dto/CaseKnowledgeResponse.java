package com.tracepcap.knowledge.dto;

import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import java.util.List;
import java.util.Map;

/** API view of the assembled knowledge board for a file (#813). */
public record CaseKnowledgeResponse(
    List<EntityDto> entities,
    List<RelationshipDto> relationships,
    List<FindingDto> findings) {

  public record EntityRefDto(String type, String key) {
    static EntityRefDto from(EntityRef ref) {
      return new EntityRefDto(ref.type().name(), ref.key());
    }
  }

  public record EntityDto(String type, String key, Map<String, Object> attributes) {}

  public record RelationshipDto(
      EntityRefDto from, String predicate, EntityRefDto to, String grade, String source, Map<String, Object> attributes) {}

  public record FindingDto(
      String category,
      String summary,
      String severity,
      String grade,
      String source,
      List<EntityRefDto> concerns,
      List<String> evidence,
      Map<String, Object> attributes) {}

  public static CaseKnowledgeResponse from(CaseKnowledge k) {
    List<EntityDto> entities =
        k.entities().stream()
            .map(e -> new EntityDto(e.type().name(), e.key(), e.attributes()))
            .toList();
    List<RelationshipDto> relationships =
        k.relationships().stream()
            .map(
                r ->
                    new RelationshipDto(
                        EntityRefDto.from(r.from()),
                        r.predicate(),
                        EntityRefDto.from(r.to()),
                        r.grade().name(),
                        r.source(),
                        r.attributes()))
            .toList();
    List<FindingDto> findings =
        k.findings().stream()
            .map(
                f ->
                    new FindingDto(
                        f.category(),
                        f.summary(),
                        f.severity().name(),
                        f.grade().name(),
                        f.source(),
                        f.concerns().stream().map(EntityRefDto::from).toList(),
                        f.evidence(),
                        f.attributes()))
            .toList();
    return new CaseKnowledgeResponse(entities, relationships, findings);
  }
}
