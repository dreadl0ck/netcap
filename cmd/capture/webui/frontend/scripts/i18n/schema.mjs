import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';
import { locales } from './config.mjs';

const require = process.env.NETCAP_I18N_DEPS_ROOT
  ? createRequire(path.join(process.env.NETCAP_I18N_DEPS_ROOT, 'package.json')) : createRequire(import.meta.url);
const { parse } = require('@formatjs/icu-messageformat-parser');

export function signature(message, locale = 'en') {
  const ast = parse(message, { ignoreTag: false, requiresOtherClause: true });
  const arguments_ = new Map();
  const selectors = [];
  function walk(elements) {
    for (const element of elements) {
      if ([1, 2, 3, 4, 5, 6].includes(element.type)) {
        const type = element.type === 6 || element.type === 2 && !element.style ? 'numeric' : `${element.type}:${JSON.stringify(element.style ?? null)}`;
        if (arguments_.has(element.value) && arguments_.get(element.value) !== type) throw new Error(`Inconsistent ICU argument: ${element.value}`);
        arguments_.set(element.value, type);
      }
      if (element.type === 5 || element.type === 6) {
        const names = Object.keys(element.options).sort();
        if (element.type === 5) selectors.push(`${element.value}:select:${names.join(',')}`);
        else {
          const allowed = new Intl.PluralRules(locale, { type: element.pluralType }).resolvedOptions().pluralCategories;
          for (const name of names) if (!name.startsWith('=') && !allowed.includes(name)) throw new Error(`Invalid ${locale} plural category: ${name}`);
          selectors.push(`${element.value}:${element.pluralType}:${element.offset}:${names.filter(name => name.startsWith('=')).join(',')}`);
        }
        Object.values(element.options).forEach(option => walk(option.value));
      }
      if (element.type === 8) { selectors.push(`tag:${element.value}`); walk(element.children); }
    }
  }
  walk(ast);
  return JSON.stringify({ arguments: [...arguments_].sort(), selectors: [...new Set(selectors)].sort() });
}

export function validateCatalogObject(catalog, label = 'catalog', { qualified = false } = {}) {
  if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog) || Object.getPrototypeOf(catalog) !== Object.prototype) throw new Error(`${label}: expected a flat JSON object`);
  for (const [key, message] of Object.entries(catalog)) {
    const pattern = qualified ? /^(?:ui|direct|removed):[a-z][a-zA-Z0-9_.-]*$/ : /^[a-z][a-zA-Z0-9_.-]*$/;
    if (!pattern.test(key) || ['constructor', 'prototype', '__proto__'].includes(key.split(':').at(-1))) throw new Error(`${label}: invalid key ${key}`);
    if (typeof message !== 'string' || !message.trim()) throw new Error(`${label}/${key}: empty/non-text message`);
  }
}

export function validateTranslation(source, translated, locale, { allowUnchanged = false, tokens = [] } = {}) {
  if (typeof translated !== 'string' || !translated.trim()) throw new Error('Empty/non-text translation');
  if (signature(source) !== signature(translated, locale)) throw new Error('ICU placeholder/select/offset mismatch');
  if (!allowUnchanged && translated.trim() === source.trim()) throw new Error('Untranslated English source');
  const english = parse(source), target = parse(translated);
  const tags = new Set();
  function collectTags(elements) { for (const node of elements) { if (node.type === 8) { tags.add(node.value); collectTags(node.children); } if (node.options) Object.values(node.options).forEach(option => collectTags(option.value)); } }
  collectTags(english);
  const tagMarker = name => `\0tag:${name}\0`;
  const invariants = [...tokens, ...[...tags].map(tagMarker)];
  if (!invariants.length) return;
  const selector = node => `${node.type}:${node.value}:${node.pluralType ?? ''}:${node.offset ?? 0}`;
  function variants(elements) {
    let result = [{ text: '', choices: {} }];
    for (const node of elements) {
      const pieces = node.type === 0 ? [{ text: node.value, choices: {} }]
        : node.type === 8 ? variants(node.children).map(item => ({ ...item, text: tagMarker(node.value) + item.text }))
        : node.type === 5 || node.type === 6 ? Object.entries(node.options).flatMap(([choice, option]) => variants(option.value).map(item => ({ text: item.text, choices: { ...item.choices, [selector(node)]: choice } })))
        : [{ text: '', choices: {} }];
      result = result.flatMap(prefix => pieces.filter(piece => Object.entries(piece.choices).every(([key, value]) => prefix.choices[key] === undefined || prefix.choices[key] === value)).map(piece => ({ text: prefix.text + piece.text, choices: { ...prefix.choices, ...piece.choices } })));
      if (result.length > 256) throw new Error('Too many ICU branch combinations');
    }
    return result;
  }
  function literals(elements, choices) {
    return elements.map(node => node.type === 0 ? node.value : node.type === 8 ? tagMarker(node.value) + literals(node.children, choices) : node.type === 5 || node.type === 6 ? literals((node.options[choices[selector(node)]] ?? node.options.other).value, choices) : '').join('');
  }
  for (const branch of variants(target)) {
    const original = literals(english, branch.choices);
    for (const token of invariants) {
      const count = text => text.split(token).length - 1;
      if (count(original) !== count(branch.text)) throw new Error(token.startsWith('\0tag:') ? `Named tag count changed: ${token.slice(5, -1)}` : `Technical token changed: ${token}`);
    }
  }
}

export function validateCatalogSet(namespace, catalogs, aliases, policy) {
    if (!['ui', 'direct', 'removed'].includes(namespace)) throw new Error(`Unknown namespace: ${namespace}`);
    const source = catalogs.en;
    validateCatalogObject(source, namespace);
    validateCatalogObject(aliases, `${namespace}/sources`);
    for (const key of Object.keys(aliases)) if (!Object.hasOwn(source, key)) throw new Error(`${namespace}/sources: unknown key ${key}`);
    const keys = Object.keys(source).sort();
    for (const locale of locales) {
      const target = catalogs[locale];
      validateCatalogObject(target, `${namespace}/${locale}`);
      if (Object.keys(target).sort().join('\0') !== keys.join('\0')) throw new Error(`${namespace}/${locale}: missing or extra keys`);
      for (const key of keys) {
        try {
          if (locale === 'en') signature(source[key]);
          else validateTranslation(source[key], target[key], locale, {
            allowUnchanged: Boolean(policy.unchanged?.[`${namespace}:${key}`]?.[locale] || policy.sourceUnchanged?.[source[key]]?.[locale] || policy.sourceUnchanged?.[source[key].trim()]?.[locale]),
            tokens: (policy.technicalTokens ?? []).filter(token => source[key].includes(token)),
          });
        } catch (error) { throw new Error(`${namespace}/${locale}/${key}: ${error.message}`); }
      }
    }
    return { namespace, messagesPerLocale: keys.length, locales: locales.length };
}

export function validateBundles(root, policy) {
  const result = [];
  for (const namespace of fs.readdirSync(root).sort()) {
    const directory = path.join(root, namespace);
    if (!fs.statSync(directory).isDirectory()) continue;
    const catalogs = Object.fromEntries(locales.map(locale => [locale, JSON.parse(fs.readFileSync(path.join(directory, `${locale}.json`), 'utf8'))]));
    const aliases = JSON.parse(fs.readFileSync(path.join(directory, 'sources.json'), 'utf8'));
    result.push(validateCatalogSet(namespace, catalogs, aliases, policy));
  }
  return result;
}
