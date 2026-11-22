import en from './en.json';
import de from './de.json';
import nl from './nl.json';
import fr from './fr.json';
import es from './es.json';
import zhHans from './zh-Hans.json';
import sources from './sources.json';
import type { CatalogBundle } from '../../runtime';

export const directCatalogBundle: CatalogBundle = {
  namespace: 'direct', catalogs: { en, de, nl, fr, es, 'zh-Hans': zhHans }, sources,
};
