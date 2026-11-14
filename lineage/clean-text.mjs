// Text one person types that another is shown as their words: a prove request's asker, a
// license invite's label. Kept apart so modules that need it don't load each other.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shown to someone else as the writer's own words, so it may hold only
 * what reads as text: letters, marks, numbers, punctuation and symbols, with any kind of
 * space turned into a plain one. Everything else is removed: control and format
 * characters (direction marks such as U+061C, U+202E; invisible operators U+2060-2064;
 * U+FEFF), line and paragraph separators (U+2028/2029), and characters that are letters
 * on paper but draw nothing (Hangul fillers U+115F, U+1160, U+3164, U+FFA0; braille blank
 * U+2800). NFKC first, so look-alike compatibility forms collapse to the plain letter.
 * Returns null for something that is not text, or longer than `max` once cleaned.
 */
export const cleanText = (v, max) => {
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string') return null;
  const s = v
    .normalize('NFKC')
    .replace(/[\p{Default_Ignorable_Code_Point}⠀]/gu, '')
    .replace(/\p{Zs}/gu, ' ')
    .replace(/[^\p{L}\p{M}\p{N}\p{P}\p{S} ]/gu, '')
    .replace(/ {2,}/g, ' ')
    .trim();
  return [...s].length > max ? null : s;
};
