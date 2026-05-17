/**
 * theme-init.js
 *
 * Resolves and applies the user's color theme BEFORE first paint to avoid
 * a light/dark flash. Loaded synchronously in <head>, so it runs before
 * the CSS is parsed. The full toggle UI logic lives in app.js.
 *
 * This file exists as a standalone asset (not inlined) so that the strict
 * CSP in app.py (`default-src 'self'`, no 'unsafe-inline') accepts it.
 */
(function () {
  try {
    var saved = localStorage.getItem('carded-theme');
    var theme =
      saved ||
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    if (theme === 'light') document.documentElement.classList.add('light');
    document.documentElement.dataset.themeResolved = theme;
  } catch (e) {
    /* localStorage / matchMedia unavailable — fall through to default dark */
  }
})();
