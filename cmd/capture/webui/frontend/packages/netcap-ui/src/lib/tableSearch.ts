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

/**
 * Parses a search query into terms, supporting negation with ! prefix.
 * Example: "HTTP !FTP admin" -> [{term: "http", negate: false}, {term: "ftp", negate: true}, {term: "admin", negate: false}]
 */
interface SearchTerm {
  term: string;
  negate: boolean;
}

export function parseSearchQuery(query: string): SearchTerm[] {
  if (!query.trim()) return [];
  
  return query
    .split(/\s+/)
    .filter(term => term.length > 0)
    .map(term => {
      if (term.startsWith('!') && term.length > 1) {
        return { term: term.slice(1).toLowerCase(), negate: true };
      }
      return { term: term.toLowerCase(), negate: false };
    });
}

/**
 * Checks if a single value matches the search terms.
 * For positive terms: at least one must match.
 * For negative terms: none must match.
 * 
 * @param value - The string value to check
 * @param searchTerms - Parsed search terms
 * @returns true if the value matches all criteria
 */
export function matchesSingleValue(value: string, searchTerms: SearchTerm[]): boolean {
  if (searchTerms.length === 0) return true;
  
  const lowerValue = value.toLowerCase();
  
  const positiveTerms = searchTerms.filter(t => !t.negate);
  const negativeTerms = searchTerms.filter(t => t.negate);
  
  // Check negative terms first - if any match, exclude this item
  if (negativeTerms.some(t => lowerValue.includes(t.term))) {
    return false;
  }
  
  // If there are positive terms, at least one must match
  if (positiveTerms.length > 0) {
    return positiveTerms.some(t => lowerValue.includes(t.term));
  }
  
  return true;
}

/**
 * Checks if an item matches the search query by checking multiple field values.
 * 
 * Search syntax:
 * - Multiple space-separated terms are OR'd together for positive matches
 * - Terms prefixed with ! are excluded (must NOT match)
 * - Examples:
 *   - "HTTP FTP" - matches if HTTP OR FTP appears in any field
 *   - "!FTP" - excludes items where FTP appears in any field  
 *   - "HTTP !FTP" - matches HTTP but excludes if FTP also appears
 * 
 * @param fieldValues - Array of string values from the item's fields to search
 * @param searchTerms - Parsed search terms
 * @returns true if the item matches all search criteria
 */
export function matchesSearchTerms(fieldValues: string[], searchTerms: SearchTerm[]): boolean {
  if (searchTerms.length === 0) return true;
  
  const positiveTerms = searchTerms.filter(t => !t.negate);
  const negativeTerms = searchTerms.filter(t => t.negate);
  
  // Combine all field values into one string for searching
  const combinedValues = fieldValues.map(v => v.toLowerCase()).join(' ');
  
  // Check negative terms first - if any match, exclude this item
  if (negativeTerms.some(t => combinedValues.includes(t.term))) {
    return false;
  }
  
  // If there are positive terms, at least one must match
  if (positiveTerms.length > 0) {
    return positiveTerms.some(t => combinedValues.includes(t.term));
  }
  
  return true;
}

/**
 * Convenience function that combines parsing and matching.
 * Filters an array of items based on a search query.
 * 
 * @param items - Array of items to filter
 * @param searchQuery - The raw search query string
 * @param getFieldValues - Function to extract searchable field values from each item
 * @returns Filtered array of items matching the search criteria
 */
export function filterBySearchQuery<T>(
  items: T[],
  searchQuery: string,
  getFieldValues: (item: T) => string[]
): T[] {
  const searchTerms = parseSearchQuery(searchQuery);
  if (searchTerms.length === 0) return items;
  
  return items.filter(item => matchesSearchTerms(getFieldValues(item), searchTerms));
}

