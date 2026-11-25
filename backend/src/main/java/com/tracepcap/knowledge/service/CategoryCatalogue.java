package com.tracepcap.knowledge.service;

import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.spi.EvidenceSource;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Every framework category with the questions that answer it and the traffic those read
 * (docs/architecture/investigation-framework.rst). Built from the auto-discovered questions, so
 * tagging a new question is all it takes to cover a category; a category no question covers is
 * still listed, with none.
 */
@Component
public class CategoryCatalogue {

  /** One category, the questions that answer it, and what they read. */
  public record Entry(Category category, List<String> questions, List<QuestionEvidence> evidence) {

    public Entry {
      questions = List.copyOf(questions);
      evidence = List.copyOf(evidence);
    }

    /** True when no question covers this category yet. */
    public boolean unchecked() {
      return questions.isEmpty();
    }
  }

  /** Traffic one question reads, and what it shows for that question. */
  public record QuestionEvidence(String question, EvidenceSource source) {}

  private final List<Entry> entries;

  public CategoryCatalogue(List<StandardQuestion> questions) {
    Map<Category, List<String>> byCategory = new EnumMap<>(Category.class);
    Map<Category, List<QuestionEvidence>> evidence = new EnumMap<>(Category.class);
    // Sorted by key, so the order doesn't depend on how Spring happened to discover them.
    List<StandardQuestion> sorted = new ArrayList<>(questions);
    sorted.sort(java.util.Comparator.comparing(StandardQuestion::question));
    for (StandardQuestion q : sorted) {
      for (Category c : q.categories()) {
        byCategory.computeIfAbsent(c, k -> new ArrayList<>()).add(q.question());
        for (EvidenceSource s : q.requires()) {
          evidence.computeIfAbsent(c, k -> new ArrayList<>()).add(new QuestionEvidence(q.question(), s));
        }
      }
    }
    List<Entry> out = new ArrayList<>();
    for (Category c : Category.values()) {
      out.add(new Entry(c, byCategory.getOrDefault(c, List.of()), evidence.getOrDefault(c, List.of())));
    }
    this.entries = List.copyOf(out);
  }

  /** Every category, in the framework's order: context, entities, then the ATT&CK tactics. */
  public List<Entry> entries() {
    return entries;
  }
}
