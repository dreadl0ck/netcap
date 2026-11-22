import labels from './schema-labels.json';
import { translate } from './runtime';

type Label = { literal?: string; key?: string };
function lookup(category: 'types' | 'fields' | 'enums', value: unknown): string {
  const raw = String(value ?? '');
  const catalog = labels[category] as Record<string, Label>;
  const normalized = category === 'enums' ? raw.toLowerCase() : raw.charAt(0).toUpperCase() + raw.slice(1);
  const label = catalog[raw] ?? catalog[normalized];
  return label?.key ? translate(label.key) : label?.literal ?? raw;
}
/** Display-only schema labels; API/filter values and unrecognized/custom IDs stay raw. */
export const recordTypeLabel = (value: unknown): string => lookup('types', value);
export const fieldLabel = (value: unknown, recordType?: string): string => recordType && !Object.prototype.hasOwnProperty.call(labels.types, recordType) ? String(value ?? '') : lookup('fields', value);
export const enumLabel = (value: unknown): string => lookup('enums', value);

const artifactKinds: Record<string, string> = { 'user-report': 'userReport', 'endpoint-result': 'endpointResult', 'proxy-nat-log': 'proxyNatLog', 'routing-interface-snapshot': 'routingSnapshot', 'debugger-stack': 'debuggerStack', other: 'other' };
export function artifactKindLabel(value: string): string { return Object.hasOwn(artifactKinds, value) ? translate(`ui:artifact.kind.${artifactKinds[value]}`) : value; }

const behaviorActions = new Set(['approve', 'pause', 'resume', 'relearn', 'reset', 'acknowledge', 'approve-changes', 'suppress', 'unsuppress']);
export function behaviorActionLabel(value: string): string { return behaviorActions.has(value) ? translate(`ui:behavior.action.${value}`) : value; }
