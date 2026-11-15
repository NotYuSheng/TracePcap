import type { GraphNode } from '@/features/network/types';
import type { NodeLabelConfig } from '@/store/slices/nodeLabelSlice';
import { deviceTypeLabel } from '@/utils/deviceType';

/**
 * Builds the ordered list of text lines drawn under a node, from the user's label
 * configuration. Cluster nodes ignore the config and keep their descriptive label.
 * Always returns at least one line so a node is never left unlabelled.
 */
export function buildNodeLines(node: GraphNode, cfg: NodeLabelConfig): string[] {
  if (node.data.isCluster) return node.label ? [node.label] : [];

  const lines: string[] = [];
  for (const opt of cfg.fields) {
    if (!opt.enabled) continue;
    let value: string | undefined;
    switch (opt.field) {
      case 'roleLabel':
        value = node.data.roleLabel;
        break;
      case 'ip':
        value = node.data.ip;
        break;
      case 'hostname':
        value = node.data.hostname;
        break;
      case 'loggedInUser':
        // Several accounts on one host (#812): flag it rather than pick one. The host's detail view
        // shows the login timeline.
        value =
          (node.data.loggedInUserCount ?? 0) > 1
            ? `${node.data.loggedInUserCount} accounts`
            : node.data.loggedInUser;
        break;
      case 'mac':
        value = node.data.mac;
        break;
      case 'deviceType':
        // Adjudicated identity is the display authority (#512 slice 5b): a human-confirmed
        // label replaces the machine type; a contested identity is marked as a question.
        if (node.data.identityBasis === 'HUMAN' && node.data.identityLabel) {
          value = node.data.identityLabel;
        } else {
          value =
            node.data.deviceType && node.data.deviceType !== 'UNKNOWN'
              ? deviceTypeLabel(node.data.deviceType)
              : undefined;
          if (value && node.data.identityContested) value += ' (contested)';
        }
        break;
      case 'manufacturer':
        value = node.data.manufacturer;
        break;
    }
    // Skip repeats: a confirmed role also becomes the HUMAN identity label, so with both the
    // role and device-type lines enabled the same text would otherwise print twice.
    if (value && !lines.includes(value)) lines.push(value);
  }
  for (const t of cfg.customText) {
    const custom = t.trim();
    if (custom) lines.push(custom);
  }
  // Never render an unlabelled node — fall back to IP (or the node's display label).
  if (lines.length === 0) lines.push(node.data.ip || node.label || '');
  return lines.filter(Boolean);
}
