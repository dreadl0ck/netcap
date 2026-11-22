/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */
import { Typography } from '@mui/material';
import { producerConsumerRatio } from '../lib/hunting';
import { translate as i18nText, formatNumber as i18nNumber, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";


export default function ProducerConsumerEvidence({ produced, consumed }: { produced: number; consumed: number }) {
  const __uiLocale = useUILocale();
  const ratio = producerConsumerRatio(produced, consumed);
  return <><Typography variant="body2" color="text.secondary">
      {i18nRichText("ui:m_c6fbe096ce167c7c878b", { arg0: ratio === null ? i18nText("ui:m_b6f62be183440dfdc4c4") : i18nNumber(ratio, { minimumFractionDigits: 3, maximumFractionDigits: 3, useGrouping: false }) })}
    </Typography><Typography variant="caption" color="text.secondary">
      {i18nText("ui:m_7a45c0e1633fc8028e5e")}
    </Typography></>;
}
