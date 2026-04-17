package com.tracepcap.layout.service;

import com.tracepcap.layout.dto.LayoutRequest;
import com.tracepcap.layout.dto.LayoutResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.elk.alg.force.options.ForceOptions;
import org.eclipse.elk.alg.layered.options.LayeredOptions;
import org.eclipse.elk.core.RecursiveGraphLayoutEngine;
import org.eclipse.elk.core.options.CoreOptions;
import org.eclipse.elk.core.options.Direction;
import org.eclipse.elk.core.util.BasicProgressMonitor;
import org.eclipse.elk.graph.ElkNode;
import org.eclipse.elk.graph.util.ElkGraphUtil;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class LayoutService {

  private final RecursiveGraphLayoutEngine engine = new RecursiveGraphLayoutEngine();

  public LayoutResponse computeLayout(LayoutRequest request) {
    log.debug(
        "Computing {} layout for {} nodes, {} edges",
        request.getLayoutType(),
        request.getNodes().size(),
        request.getEdges().size());

    ElkNode root = ElkGraphUtil.createGraph();

    if ("hierarchicalTd".equals(request.getLayoutType())) {
      root.setProperty(CoreOptions.ALGORITHM, "org.eclipse.elk.layered");
      root.setProperty(CoreOptions.DIRECTION, Direction.DOWN);
      root.setProperty(CoreOptions.SEPARATE_CONNECTED_COMPONENTS, true);
      root.setProperty(CoreOptions.SPACING_NODE_NODE, 40.0);
      root.setProperty(LayeredOptions.SPACING_NODE_NODE_BETWEEN_LAYERS, 80.0);
    } else {
      root.setProperty(CoreOptions.ALGORITHM, "org.eclipse.elk.force");
      root.setProperty(CoreOptions.SEPARATE_CONNECTED_COMPONENTS, true);
      root.setProperty(CoreOptions.SPACING_NODE_NODE, 80.0);
      root.setProperty(ForceOptions.ITERATIONS, 500);
      root.setProperty(ForceOptions.REPULSION, 5.0);
    }

    Map<String, ElkNode> nodeMap = new HashMap<>();
    for (LayoutRequest.LayoutNode n : request.getNodes()) {
      ElkNode elkNode = ElkGraphUtil.createNode(root);
      elkNode.setIdentifier(n.getId());
      elkNode.setWidth(n.getWidth());
      elkNode.setHeight(n.getHeight());
      nodeMap.put(n.getId(), elkNode);
    }

    for (LayoutRequest.LayoutEdge e : request.getEdges()) {
      ElkNode src = nodeMap.get(e.getSource());
      ElkNode tgt = nodeMap.get(e.getTarget());
      if (src == null || tgt == null) continue;
      ElkGraphUtil.createSimpleEdge(src, tgt);
    }

    try {
      engine.layout(root, new BasicProgressMonitor());
    } catch (Exception ex) {
      log.error("ELK layout failed", ex);
      throw new RuntimeException("Layout computation failed: " + ex.getMessage(), ex);
    }

    List<LayoutResponse.NodePosition> positions =
        root.getChildren().stream()
            .map(n -> new LayoutResponse.NodePosition(n.getIdentifier(), n.getX(), n.getY()))
            .collect(Collectors.toList());

    log.debug("Layout complete, {} positions computed", positions.size());
    return new LayoutResponse(positions);
  }
}
