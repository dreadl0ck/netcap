/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */
import { Typography } from '@mui/material';
import { producerConsumerRatio } from '../lib/hunting';

export default function ProducerConsumerEvidence({ produced, consumed }: { produced: number; consumed: number }) {
  const ratio = producerConsumerRatio(produced, consumed);
  return <>
    <Typography variant="body2" color="text.secondary">
      Producer–consumer ratio: {ratio === null ? 'Unavailable' : ratio.toFixed(3)}
    </Typography>
    <Typography variant="caption" color="text.secondary">
      −1 consumes, +1 produces. Derived from observed client/server bytes; backups and asymmetric capture can also produce extreme ratios.
    </Typography>
  </>;
}
