/**
 * Carded — app.js
 *
 * Vanilla JS UI controller for the Carded business card scanner.
 *
 * Security contract (mirrors §B of the interface contract):
 *   - NEVER assign user/LLM content to .innerHTML, .outerHTML, or document.write.
 *   - ALL text from the server (card fields, error messages, error.detail) is
 *     rendered exclusively via .textContent or createTextNode().
 *   - URL fields are validated with new URL() before being used as href values.
 *     Any URL that fails parsing is rendered as plain text.
 */

'use strict';

/* ============================================================
   DOM refs — grabbed once after DOMContentLoaded
   ============================================================ */
let refs = {};

// The file currently chosen for upload. Tracked here (not just on the
// file input) so drag-and-drop and the picker converge on a single source
// of truth. Browsers restrict programmatic FileList assignment, so a
// dropped file may not appear in fileInput.files in every browser.
let selectedFile = null;

// The most recent object URL passed to the preview <img>, kept so we can
// revoke it before assigning a new one (avoids leaking blob references).
let currentPreviewUrl = null;

function initRefs() {
  refs = {
    // API key section
    apiKeySection:  document.getElementById('api-key-section'),
    keyIndicator:   document.getElementById('key-indicator'),
    keyMask:        document.getElementById('key-mask'),
    keyEntry:       document.getElementById('key-entry'),
    keyForm:        document.getElementById('key-form'),
    apiKeyInput:    document.getElementById('api-key-input'),
    saveKeyBtn:     document.getElementById('save-key-btn'),
    changeKeyBtn:   document.getElementById('change-key-btn'),
    keyError:       document.getElementById('key-error'),

    // Upload section
    uploadSection:  document.getElementById('upload-section'),
    uploadForm:     document.getElementById('upload-form'),
    fileInput:      document.getElementById('file-input'),
    fileDropZone:   document.getElementById('file-drop-zone'),
    previewArea:    document.getElementById('preview-area'),
    previewImg:     document.getElementById('preview-img'),
    previewFilename: document.getElementById('preview-filename'),
    clearFileBtn:   document.getElementById('clear-file-btn'),
    errorCard:      document.getElementById('error-card'),
    errorMessage:   document.getElementById('error-message'),
    errorDetail:    document.getElementById('error-detail'),
    submitBtn:      document.getElementById('submit-btn'),
    submitLabel:    document.getElementById('submit-label'),
    submitSpinner:  document.getElementById('submit-spinner'),

    // Result section
    resultSection:  document.getElementById('result-section'),
    resultCard:     document.getElementById('result-card'),
    vcfLink:        document.getElementById('vcf-link'),
    csvLink:        document.getElementById('csv-link'),
  };
}

/* ============================================================
   Loading state
   ============================================================ */
function showLoading() {
  refs.submitBtn.disabled = true;
  refs.submitLabel.textContent = 'Reading card…';
  refs.submitSpinner.classList.remove('spinner--hidden');
  refs.submitSpinner.removeAttribute('aria-hidden');
}

function hideLoading() {
  refs.submitBtn.disabled = selectedFile === null;
  refs.submitLabel.textContent = 'Extract card';
  refs.submitSpinner.classList.add('spinner--hidden');
  refs.submitSpinner.setAttribute('aria-hidden', 'true');
}

/* ============================================================
   Image preview
   ============================================================ */
function previewImage(file) {
  // Revoke the previous object URL before creating a new one (avoids
  // accumulating blob references across selections).
  if (currentPreviewUrl) {
    URL.revokeObjectURL(currentPreviewUrl);
    currentPreviewUrl = null;
  }

  const objectUrl = URL.createObjectURL(file);
  currentPreviewUrl = objectUrl;

  // Reset to the "image visible" state. If the browser fails to render
  // the file (HEIC in Chrome/Firefox, corrupted bytes), onerror flips
  // the area to fallback mode so we never show a broken-image icon.
  refs.previewArea.classList.remove('preview-area--no-image');
  refs.previewFilename.textContent = file.name;

  refs.previewImg.onerror = () => {
    refs.previewArea.classList.add('preview-area--no-image');
  };
  refs.previewImg.onload = () => {
    refs.previewArea.classList.remove('preview-area--no-image');
  };

  refs.previewImg.src = objectUrl;
  refs.previewArea.classList.remove('preview-area--hidden');
}

function clearFile() {
  selectedFile = null;
  refs.fileInput.value = '';
  if (currentPreviewUrl) {
    URL.revokeObjectURL(currentPreviewUrl);
    currentPreviewUrl = null;
  }
  // Detach handlers and use removeAttribute (rather than src='') so the
  // browser does not attempt to load an empty resource.
  refs.previewImg.onerror = null;
  refs.previewImg.onload = null;
  refs.previewImg.removeAttribute('src');
  refs.previewArea.classList.add('preview-area--hidden');
  refs.previewArea.classList.remove('preview-area--no-image');
  refs.previewFilename.textContent = '';
  refs.submitBtn.disabled = true;
  hideErrorCard();
}

/* ============================================================
   Error rendering
   ============================================================ */
function hideErrorCard() {
  refs.errorCard.classList.add('error-card--hidden');
  refs.errorMessage.textContent = '';
  refs.errorDetail.textContent = '';
}

/**
 * renderError — renders server error JSON safely.
 *
 * SECURITY: both message and detail are assigned via .textContent.
 * detail is LLM-generated (attacker-controllable) per §B of the contract.
 *
 * @param {{ error: string, message: string, detail?: string }} errorJson
 */
function renderError(errorJson) {
  refs.errorCard.classList.remove('error-card--hidden');

  // message is server-controlled text but we still use .textContent for consistency
  refs.errorMessage.textContent = errorJson.message || 'An unexpected error occurred.';

  // detail MUST use .textContent — it is LLM-generated / attacker-controllable
  if (errorJson.detail) {
    refs.errorDetail.textContent = errorJson.detail;
    refs.errorDetail.removeAttribute('hidden');
  } else {
    refs.errorDetail.textContent = '';
    refs.errorDetail.setAttribute('hidden', '');
  }

  refs.errorCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ============================================================
   API key management
   ============================================================ */
function showKeyError(msg) {
  refs.keyError.textContent = msg;
  refs.keyError.classList.remove('key-error--hidden');
}

function hideKeyError() {
  refs.keyError.textContent = '';
  refs.keyError.classList.add('key-error--hidden');
}

/**
 * setApiKey — POSTs the API key to /session/key.
 * On success, collapses the key entry form and shows the upload UI.
 *
 * @param {string} key
 */
async function setApiKey(key) {
  hideKeyError();

  // Basic client-side format check to give faster feedback (server validates authoritatively)
  if (!key.startsWith('sk-ant-')) {
    showKeyError("API key must begin with ‘sk-ant-’.");
    refs.apiKeyInput.focus();
    return;
  }

  refs.saveKeyBtn.disabled = true;
  refs.saveKeyBtn.textContent = 'Saving…';

  try {
    const resp = await fetch('/session/key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key }),
      credentials: 'same-origin',
    });

    const data = resp.ok ? {} : await resp.json().catch(() => ({}));

    if (resp.ok) {
      // Show indicator, hide entry form, reveal upload section
      revealKeyIndicator(key);
      refs.uploadSection.classList.remove('upload-section--hidden');
    } else {
      const msg = data.message || 'Could not save the key. Please try again.';
      showKeyError(msg);
    }
  } catch (_err) {
    showKeyError('Network error. Please check your connection and try again.');
  } finally {
    refs.saveKeyBtn.disabled = false;
    refs.saveKeyBtn.textContent = 'Save key';
  }
}

/**
 * Build the masked key string: show first 10 chars, then "...", then last 4.
 * e.g.  sk-ant-api0...wxyz
 */
function maskKey(key) {
  if (key.length <= 14) return key;
  return key.slice(0, 10) + '…' + key.slice(-4);
}

function revealKeyIndicator(key) {
  // The indicator block is always present in the DOM. Update its mask
  // text via .textContent (user-supplied input, never DOM) and reveal it
  // by removing the hidden modifier class.
  refs.keyMask.textContent = maskKey(key);
  refs.keyIndicator.classList.remove('key-indicator--hidden');
  refs.apiKeySection.classList.add('api-key-section--set');
  refs.keyEntry.classList.add('key-entry--hidden');
}

/* ============================================================
   Card submission
   ============================================================ */
/**
 * submitCard — POSTs the image file to /process.
 * Handles 200, 4xx, 5xx branches according to the interface contract.
 *
 * @param {File} file
 */
async function submitCard(file) {
  if (!file) {
    renderError({
      error: 'no_file',
      message: 'Please choose a business card image before extracting.',
    });
    return;
  }

  hideErrorCard();
  hideResultSection();
  showLoading();

  const formData = new FormData();
  formData.append('file', file);

  try {
    const resp = await fetch('/process', {
      method: 'POST',
      body: formData,
      credentials: 'same-origin',
    });

    const data = await resp.json().catch(() => null);

    if (resp.ok && data) {
      // SUCCESS — render card and show downloads
      renderCard(data.card);
      const token = data.token;
      refs.vcfLink.href = '/download/vcf?token=' + encodeURIComponent(token);
      refs.csvLink.href = '/download/csv?token=' + encodeURIComponent(token);
      showResultSection();
      // Reset the upload form so the next scan starts from a clean state
      // (no stale file, no lingering preview). The form itself stays
      // visible so the user can scan another card if they want.
      clearFile();
    } else if (resp.status === 401 && data && data.error === 'missing_api_key') {
      // Scroll back to key entry
      scrollToKeyEntry(data);
    } else if (data) {
      renderError(data);
    } else {
      renderError({
        error: 'unknown',
        message: 'An unexpected error occurred. Please try again.',
      });
    }
  } catch (_err) {
    renderError({
      error: 'network',
      message: 'Network error. Please check your connection and try again.',
    });
  } finally {
    hideLoading();
  }
}

function scrollToKeyEntry(errorJson) {
  // Show the key entry form again
  refs.keyEntry.classList.remove('key-entry--hidden');
  refs.apiKeySection.classList.remove('api-key-section--set');
  // Surface the message in the key error area
  showKeyError(errorJson.message || 'Please enter your Anthropic API key to continue.');
  refs.apiKeySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  refs.apiKeyInput.focus();
}

/* ============================================================
   Result rendering
   ============================================================ */
function showResultSection() {
  refs.resultSection.classList.remove('result-section--hidden');
  refs.resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideResultSection() {
  refs.resultSection.classList.add('result-section--hidden');
  // Clear previous result content safely
  while (refs.resultCard.firstChild) {
    refs.resultCard.removeChild(refs.resultCard.firstChild);
  }
}

/**
 * el — tiny helper: create element with optional class list.
 * @param {string} tag
 * @param {...string} classNames
 */
function el(tag, ...classNames) {
  const node = document.createElement(tag);
  if (classNames.length) node.className = classNames.join(' ');
  return node;
}

/**
 * txt — create a text node.
 * @param {string} content
 */
function txt(content) {
  return document.createTextNode(String(content));
}

/**
 * appendField — adds a labeled row to a container.
 * Both label and value are set via .textContent / createTextNode.
 *
 * @param {HTMLElement} container
 * @param {string} label
 * @param {HTMLElement|string} valueNodeOrString  — can be a pre-built element
 */
function appendField(container, label, valueNodeOrString) {
  const row = el('div', 'result-field');

  const labelEl = el('span', 'result-field__label');
  labelEl.textContent = label;
  row.appendChild(labelEl);

  const valueEl = el('span', 'result-field__value');
  if (typeof valueNodeOrString === 'string') {
    valueEl.textContent = valueNodeOrString;
  } else {
    valueEl.appendChild(valueNodeOrString);
  }
  row.appendChild(valueEl);

  container.appendChild(row);
}

/**
 * safeLink — build an <a> element if url parses; otherwise a <span>.
 * SECURITY: href only set if new URL() succeeds. textContent for display.
 *
 * @param {string} urlString
 * @returns {HTMLElement}
 */
function safeLink(urlString) {
  try {
    const parsed = new URL(urlString);
    // Only allow http and https schemes
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('unsafe scheme');
    }
    const a = el('a');
    a.href = parsed.href;
    a.rel = 'noopener noreferrer';
    a.target = '_blank';
    a.textContent = urlString;
    return a;
  } catch (_e) {
    const span = el('span');
    span.textContent = urlString;
    return span;
  }
}

/**
 * renderCard — builds the result UI from BAML card JSON.
 *
 * SECURITY: ALL card fields are LLM-derived text that corresponds to literal
 * card content. Still treated as untrusted — every value goes through
 * .textContent or safeLink(). No .innerHTML anywhere.
 *
 * @param {object} card  — BusinessCardJson per the interface contract §A
 */
function renderCard(card) {
  const container = refs.resultCard;
  // Clear previous content without innerHTML
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  /* ── Name block ─────────────────────────────────────── */
  const nameBlock = el('div', 'result-name');

  // Build display name: prefer full_name, else compose from parts
  let displayName = null;
  if (card.full_name) {
    displayName = card.full_name;
  } else {
    const parts = [card.prefix, card.first_name, card.last_name, card.suffix]
      .filter(Boolean);
    if (parts.length) displayName = parts.join(' ');
  }

  if (displayName) {
    const nameEl = el('p', 'result-name__full');
    nameEl.textContent = displayName;
    nameBlock.appendChild(nameEl);
  }

  // Subtitle: title @ organization
  const subtitleParts = [card.title, card.organization].filter(Boolean);
  if (subtitleParts.length) {
    const subtitleEl = el('p', 'result-name__subtitle');
    subtitleEl.textContent = subtitleParts.join(' · ');
    nameBlock.appendChild(subtitleEl);
  }

  if (card.department) {
    const deptEl = el('p', 'result-name__department');
    deptEl.textContent = card.department;
    nameBlock.appendChild(deptEl);
  }

  container.appendChild(nameBlock);

  /* ── Field rows ─────────────────────────────────────── */
  const fields = el('div', 'result-fields');

  // Phones
  if (card.phones && card.phones.length) {
    const entriesEl = el('div', 'result-entries');
    card.phones.forEach(function (phone) {
      const entry = el('div', 'result-entry');
      const numSpan = el('span', 'result-entry__text');
      numSpan.textContent = phone.number;
      const typeSpan = el('span', 'result-entry__type');
      typeSpan.textContent = phone.type;
      entry.appendChild(numSpan);
      entry.appendChild(typeSpan);
      entriesEl.appendChild(entry);
    });
    appendField(fields, 'Phone', entriesEl);
  }

  // Emails
  if (card.emails && card.emails.length) {
    const entriesEl = el('div', 'result-entries');
    card.emails.forEach(function (email) {
      const entry = el('div', 'result-entry');
      const addrSpan = el('span', 'result-entry__text');
      addrSpan.textContent = email.address;
      const typeSpan = el('span', 'result-entry__type');
      typeSpan.textContent = email.type;
      entry.appendChild(addrSpan);
      entry.appendChild(typeSpan);
      entriesEl.appendChild(entry);
    });
    appendField(fields, 'Email', entriesEl);
  }

  // URLs
  if (card.urls && card.urls.length) {
    const entriesEl = el('div', 'result-entries');
    card.urls.forEach(function (url) {
      const entry = el('div', 'result-entry');
      entry.appendChild(safeLink(url));
      entriesEl.appendChild(entry);
    });
    appendField(fields, 'Web', entriesEl);
  }

  // Address
  if (card.address) {
    const addr = card.address;
    const addrParts = [];
    if (addr.street)      addrParts.push(addr.street);
    if (addr.street2)     addrParts.push(addr.street2);
    // City, State ZIP
    const cityLine = [addr.city, addr.state].filter(Boolean).join(', ');
    const cityZip  = [cityLine, addr.postal_code].filter(Boolean).join(' ');
    if (cityZip)          addrParts.push(cityZip);
    if (addr.country)     addrParts.push(addr.country);

    if (addrParts.length) {
      const addrEl = el('span');
      addrEl.textContent = addrParts.join('\n');
      addrEl.style.whiteSpace = 'pre-line';
      appendField(fields, 'Address', addrEl);
    }
  }

  // LinkedIn
  if (card.linkedin) {
    // LinkedIn may be a handle or URL; try to wrap in a URL if not already
    const linkedinNode = isUrl(card.linkedin)
      ? safeLink(card.linkedin)
      : safeLink('https://' + card.linkedin);
    appendField(fields, 'LinkedIn', linkedinNode);
  }

  // Twitter
  if (card.twitter) {
    appendField(fields, 'Twitter', card.twitter);
  }

  // Instagram
  if (card.instagram) {
    appendField(fields, 'Instagram', card.instagram);
  }

  if (fields.children.length) {
    container.appendChild(fields);
  }

  /* ── Note ───────────────────────────────────────────── */
  if (card.note) {
    const noteSection = el('div', 'result-note');
    const noteText = el('p', 'result-note__text');
    noteText.textContent = card.note;
    noteSection.appendChild(noteText);
    container.appendChild(noteSection);
  }
}

/**
 * isUrl — returns true if the string can be parsed as http(s) URL.
 * Used to decide whether to prepend https:// to social handles.
 *
 * @param {string} str
 */
function isUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_e) {
    return false;
  }
}

/* ============================================================
   Drag-and-drop enhancement
   ============================================================ */
function initDragDrop() {
  const zone = refs.fileDropZone;
  if (!zone) return;

  zone.addEventListener('dragover', function (e) {
    e.preventDefault();
    zone.classList.add('is-drag-over');
  });

  zone.addEventListener('dragleave', function () {
    zone.classList.remove('is-drag-over');
  });

  zone.addEventListener('drop', function (e) {
    e.preventDefault();
    zone.classList.remove('is-drag-over');
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) {
      handleFileSelected(file);
    }
  });
}

/* ============================================================
   File selection handler
   ============================================================ */
function handleFileSelected(file) {
  if (!file) return;
  selectedFile = file;
  previewImage(file);
  refs.submitBtn.disabled = false;
  hideErrorCard();
}

/* ============================================================
   Event wiring
   ============================================================ */
function initEvents() {
  // API key form submit
  if (refs.keyForm) {
    refs.keyForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const key = (refs.apiKeyInput.value || '').trim();
      if (key) setApiKey(key);
    });
  }

  // "Change" button: clear the encrypted key on the server, then re-show
  // the entry form. Mirrors Receipt Ranger UX — refreshing the page after
  // clicking Change should also show the entry form (because the cookie
  // is gone), not the previously-set indicator.
  if (refs.changeKeyBtn) {
    refs.changeKeyBtn.addEventListener('click', async function () {
      refs.changeKeyBtn.disabled = true;
      try {
        await fetch('/session/key', {
          method: 'DELETE',
          credentials: 'same-origin',
        });
      } catch (_err) {
        // Even if the network call fails, fall through and reset the UI;
        // the cookie may still be set, but the user can retry.
      }
      refs.keyEntry.classList.remove('key-entry--hidden');
      refs.keyIndicator.classList.add('key-indicator--hidden');
      refs.apiKeySection.classList.remove('api-key-section--set');
      refs.apiKeyInput.value = '';
      refs.uploadSection.classList.add('upload-section--hidden');
      hideResultSection();
      clearFile();
      refs.changeKeyBtn.disabled = false;
      refs.apiKeyInput.focus();
    });
  }

  // File input change
  if (refs.fileInput) {
    refs.fileInput.addEventListener('change', function () {
      const file = refs.fileInput.files[0];
      handleFileSelected(file);
    });
  }

  // Clear file button
  if (refs.clearFileBtn) {
    refs.clearFileBtn.addEventListener('click', clearFile);
  }

  // Upload form submit. Uses the closure-tracked selectedFile so dropped
  // files work the same as picked files. If somehow no file is set, the
  // submitCard() guard renders a visible error instead of failing silently.
  if (refs.uploadForm) {
    refs.uploadForm.addEventListener('submit', function (e) {
      e.preventDefault();
      submitCard(selectedFile);
    });
  }

  // Drag-and-drop
  initDragDrop();
}

/* ============================================================
   Theme toggle
   ------------------------------------------------------------
   The initial class is applied by an inline script in base.html
   (pre-paint, to avoid a flash). This handler only swaps the
   class and persists the user's choice. localStorage may be
   unavailable (private browsing, blocked storage) — fail open.
   ============================================================ */
function initThemeToggle() {
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;

  function syncLabel(isLight) {
    toggle.setAttribute(
      'aria-label',
      isLight ? 'Switch to dark theme' : 'Switch to light theme'
    );
    toggle.setAttribute('aria-pressed', String(isLight));
  }

  syncLabel(document.documentElement.classList.contains('light'));

  toggle.addEventListener('click', function () {
    const root = document.documentElement;
    const nextLight = !root.classList.contains('light');
    root.classList.toggle('light', nextLight);
    syncLabel(nextLight);
    try {
      localStorage.setItem('carded-theme', nextLight ? 'light' : 'dark');
    } catch (e) {
      /* storage unavailable — preference is session-only */
    }
  });
}

/* ============================================================
   Boot
   ============================================================ */
document.addEventListener('DOMContentLoaded', function () {
  initRefs();
  initEvents();
  initThemeToggle();
});
