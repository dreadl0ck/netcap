/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

// Shared chart-type catalog used by Explore and Dashboards features.
// Kept as data-only (no JSX) so it can be imported into any module without
// pulling in MUI icons.

export interface ChartTypeDef {
  value: string;
  label: string;
  description: string;
  forNumeric?: boolean;
  forCategorical?: boolean;
}

export const CHART_TYPES: ChartTypeDef[] = [
  { value: 'line', label: 'Line Chart', description: 'Time series with smooth lines', forNumeric: true },
  { value: 'bar', label: 'Bar Chart', description: 'Vertical bars for comparison', forNumeric: true, forCategorical: true },
  { value: 'area', label: 'Area Chart', description: 'Filled area under line', forNumeric: true },
  { value: 'scatter', label: 'Scatter Plot', description: 'Individual data points', forNumeric: true },
  { value: 'funnel', label: 'Funnel Chart', description: 'Value progression funnel', forNumeric: true, forCategorical: true },
  { value: 'radar', label: 'Radar Chart', description: 'Multi-dimensional comparison', forNumeric: true },
  { value: 'pie', label: 'Pie Chart', description: 'Distribution of categories', forCategorical: true },
  { value: 'wordcloud', label: 'Word Cloud', description: 'Text frequency visualization', forCategorical: true },
  { value: 'sankey', label: 'Sankey Diagram', description: 'Flow and relationships', forCategorical: true },
  { value: 'graph', label: 'Network Graph', description: 'Network relationships', forCategorical: true },
];

export function getChartTypeLabel(value: string): string {
  return CHART_TYPES.find((c) => c.value === value)?.label || value;
}
