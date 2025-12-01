/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { PieChart } from 'echarts/charts';
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

// Register only the components we need
echarts.use([
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  PieChart,
  CanvasRenderer,
]);

interface PieChartClickParams {
  name: string;
  value: number;
  dataIndex: number;
}

interface OptimizedPieChartProps {
  option: echarts.EChartsCoreOption;
  style?: React.CSSProperties;
  onItemClick?: (params: PieChartClickParams) => void;
}

export default function OptimizedPieChart({ option, style, onItemClick }: OptimizedPieChartProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstanceRef = useRef<echarts.ECharts | null>(null);
  const onItemClickRef = useRef(onItemClick);

  // Keep callback ref updated without triggering effect
  useEffect(() => {
    onItemClickRef.current = onItemClick;
  }, [onItemClick]);

  useEffect(() => {
    if (!chartRef.current) return;

    // Initialize chart if not exists
    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    // Set option
    chartInstanceRef.current.setOption(option);

    // Add click handler
    const handleClick = (params: echarts.ECElementEvent) => {
      if (onItemClickRef.current && params.name !== undefined) {
        onItemClickRef.current({
          name: params.name as string,
          value: typeof params.value === 'number' ? params.value : 0,
          dataIndex: params.dataIndex ?? 0,
        });
      }
    };

    chartInstanceRef.current.on('click', handleClick);

    // Cleanup
    return () => {
      chartInstanceRef.current?.off('click', handleClick);
      chartInstanceRef.current?.dispose();
      chartInstanceRef.current = null;
    };
  }, [option]);

  // Handle resize
  useEffect(() => {
    const handleResize = () => {
      chartInstanceRef.current?.resize();
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return <div ref={chartRef} style={{ cursor: onItemClick ? 'pointer' : 'default', ...style }} />;
}

