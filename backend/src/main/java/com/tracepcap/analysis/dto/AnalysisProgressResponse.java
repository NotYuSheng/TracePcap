package com.tracepcap.analysis.dto;

/**
 * Live analysis progress for a file being analysed. Reported at each stage boundary of the pipeline
 * (see {@code AnalysisService.analyzeFile}) so the loading view can show real milestones instead of
 * a time-interpolated guess.
 *
 * <p>{@code percent} is the weighted fraction of work completed <em>before</em> the current stage
 * started — it holds steady while an opaque external stage (Suricata, nDPI, file extraction) runs,
 * because those subprocesses expose no interior progress. The frontend animates the bar to convey
 * "still working" without fabricating movement.
 *
 * @param stageIndex 1-based index of the stage currently running
 * @param totalStages number of stages that will run for this file (skipped stages are excluded)
 * @param stage human-readable label of the current stage
 * @param percent weighted completion 0-100 at the start of the current stage
 */
public record AnalysisProgressResponse(
    int stageIndex, int totalStages, String stage, int percent) {}
