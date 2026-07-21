// i18n/index.ts — Internationalization hook + context
// Lightweight i18n without external dependencies.
// Language persists in localStorage. Default: English.

import { useState, useCallback, useMemo } from 'react';
import { en, type Translations } from './en';
import { de } from './de';

export type Language = 'en' | 'de';

const LANGUAGES: Record<Language, Translations> = { en, de };
const STORAGE_KEY = 'electrumsv-mc-language';

/** Read stored language or default to English. */
function getStoredLanguage(): Language {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'en' || stored === 'de') return stored;
  } catch {
    // localStorage not available (SSR / test env)
  }
  return 'en';
}

/** Store language preference. */
function setStoredLanguage(lang: Language): void {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // ignore
  }
}

/**
 * Hook providing the current language, a setter, and a `t` function.
 *
 * Usage:
 *   const { t, language, setLanguage } = useTranslation();
 *   <h1>{t.landing.title}</h1>
 *   <button onClick={() => setLanguage('de')}>Deutsch</button>
 *
 * The `t` object is the translation dictionary for the current language.
 * Interpolation: use {placeholder} syntax in translation strings,
 * then call t.section.key with replacements — but for simplicity we
 * expose the raw dictionary and let components do interpolation inline.
 */
export function useTranslation() {
  const [language, setLanguageState] = useState<Language>(getStoredLanguage);

  const setLanguage = useCallback((lang: Language) => {
    setLanguageState(lang);
    setStoredLanguage(lang);
  }, []);

  const t = useMemo(() => LANGUAGES[language], [language]);

  return { t, language, setLanguage };
}

/**
 * Interpolation helper — replaces {placeholder} with values.
 *
 *   interp(t.login.backupWarning, { count: 12 })
 *   → "⚠ Write down these 12 words and keep them safe. ..."
 */
export function interp(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, key) => String(values[key] ?? `{${key}}`));
}

export { type Translations };