/**
 * Coal Crypto Vault — app.js
 * Rolling-XOR + ROL 3 cipher · Python bridge + JS fallback
 * Zero external dependencies
 */

'use strict';

/* ═══════════════════════════════════════════════════════════════
   1. CIPHER ENGINE  (client-side mirror of the Python/ASM logic)
   ═══════════════════════════════════════════════════════════════
   Encrypt: for each byte b[i], key byte k[i % keyLen]:
     1. XOR:  x = b[i] ^ k[i % keyLen]  (rolling — key byte rolls with i)
     2. ROL3: y = ((x << 3) | (x >> 5)) & 0xFF
   Decrypt: reverse — ROR 3 first, then XOR with same key byte.
*/

/**
 * Rotate-left 3 bits on an 8-bit value.
 * @param {number} byte  0–255
 * @returns {number}
 */
function rol3(byte) {
  return ((byte << 3) | (byte >>> 5)) & 0xFF;
}

/**
 * Rotate-right 3 bits on an 8-bit value.
 * @param {number} byte  0–255
 * @returns {number}
 */
function ror3(byte) {
  return ((byte >>> 3) | (byte << 5)) & 0xFF;
}

/**
 * Build a Uint8Array key buffer from a string (UTF-8).
 * @param {string} keyStr
 * @returns {Uint8Array}
 */
function keyBytes(keyStr) {
  return new TextEncoder().encode(keyStr);
}

/**
 * Core transform.  Returns both the result bytes and per-step debug info.
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {'encrypt'|'decrypt'} mode
 * @returns {{ output: Uint8Array, steps: Array }}
 */
function runCipher(input, key, mode) {
  if (key.length === 0) throw new Error('Key must not be empty.');

  const out   = new Uint8Array(input.length);
  const steps = [];           // { idx, char, inByte, xorByte, keyByte, outByte }

  for (let i = 0; i < input.length; i++) {
    const inByte  = input[i];
    const kByte   = key[i % key.length];
    let   outByte;

    if (mode === 'encrypt') {
      const xored = inByte ^ kByte;
      outByte     = rol3(xored);
      steps.push({ idx: i, inByte, kByte, xored, outByte, mode });
    } else {
      const rored = ror3(inByte);
      outByte     = rored ^ kByte;
      steps.push({ idx: i, inByte, kByte, xored: rored ^ kByte, outByte, mode });
    }

    out[i] = outByte;
  }

  return { output: out, steps };
}

/**
 * Encode a Uint8Array as Base64.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * Decode a Base64 string to Uint8Array.
 * @param {string} b64
 * @returns {Uint8Array}
 */
function fromBase64(b64) {
  const bin  = atob(b64);
  const arr  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

/* ═══════════════════════════════════════════════════════════════
   2. KEY STRENGTH ANALYSIS
   ═══════════════════════════════════════════════════════════════ */

/**
 * Returns { score: 0–100, grade, criteria } for a given key string.
 */
function analyzeKey(key) {
  const criteria = {
    len:   key.length >= 8,
    upper: /[A-Z]/.test(key),
    digit: /[0-9]/.test(key),
    sym:   /[^A-Za-z0-9]/.test(key),
    long:  key.length >= 16,
  };

  // Score breakdown: each criterion contributes a share
  const weights = { len: 20, upper: 20, digit: 20, sym: 25, long: 15 };
  let score = 0;
  for (const [k, v] of Object.entries(criteria)) {
    if (v) score += weights[k];
  }

  // Length bonus (up to 5 extra) — smooth ramp beyond 16 chars
  const lengthBonus = Math.min(5, Math.floor((key.length - 16) / 4));
  if (key.length > 16) score = Math.min(100, score + Math.max(0, lengthBonus));

  let grade;
  if      (score >= 90) grade = 'STRONG';
  else if (score >= 65) grade = 'GOOD';
  else if (score >= 40) grade = 'FAIR';
  else if (score >= 15) grade = 'WEAK';
  else                  grade = 'NONE';

  return { score, grade, criteria };
}

/** Grade → CSS colour token name */
function gradeColor(grade) {
  return { STRONG: '#00ff88', GOOD: '#00e5ff', FAIR: '#ffd60a', WEAK: '#ff8c42', NONE: '#ff3a5c' }[grade] ?? '#ff3a5c';
}

/* ═══════════════════════════════════════════════════════════════
   3. HEX DUMP BUILDER
   ═══════════════════════════════════════════════════════════════ */

/**
 * Produces a formatted hex dump string with coloured spans.
 * @param {Uint8Array} bytes
 * @param {number} width  bytes per row (default 16)
 * @returns {string}  HTML string for innerHTML
 */
function buildHexDump(bytes, width = 16) {
  if (!bytes || bytes.length === 0) return '<span class="hex-np">— empty —</span>';

  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += width) {
    const row     = bytes.slice(offset, offset + width);
    const addrStr = offset.toString(16).padStart(8, '0').toUpperCase();

    // Hex bytes section
    const hexParts = [];
    for (let j = 0; j < width; j++) {
      if (j < row.length) {
        hexParts.push(`<span class="hex-byte">${row[j].toString(16).padStart(2, '0').toUpperCase()}</span>`);
      } else {
        hexParts.push('  ');
      }
      if (j === 7) hexParts.push('<span class="hex-sep"> │ </span>');
    }

    // ASCII section
    const asciiParts = [];
    for (let j = 0; j < row.length; j++) {
      const c = row[j];
      if (c >= 0x20 && c < 0x7F) {
        // Escape HTML special chars
        const ch = String.fromCharCode(c)
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        asciiParts.push(`<span class="hex-ascii">${ch}</span>`);
      } else {
        asciiParts.push(`<span class="hex-np">·</span>`);
      }
    }

    rows.push(
      `<span class="hex-addr">${addrStr}</span>` +
      `<span class="hex-sep">  │  </span>` +
      hexParts.join(' ') +
      `<span class="hex-sep">  │  </span>` +
      asciiParts.join('')
    );
  }

  return rows.join('\n');
}

/* ═══════════════════════════════════════════════════════════════
   4. STEP TABLE BUILDER (XOR + ROL/ROR)
   ═══════════════════════════════════════════════════════════════ */

/**
 * Builds the XOR steps HTML table rows.
 * @param {Array} steps — from runCipher
 * @param {'encrypt'|'decrypt'} mode
 * @returns {string}  HTML
 */
function buildXorSteps(steps, mode) {
  if (!steps || steps.length === 0) return '<p class="steps-placeholder">— run an operation to populate —</p>';

  const MAX_DISPLAY = 128;
  const limited     = steps.slice(0, MAX_DISPLAY);

  const header = `
    <div class="step-row step-row-header">
      <span class="step-col-label">#</span>
      <span class="step-col-label">Char</span>
      <span class="step-col-label">In (hex)</span>
      <span class="step-col-label">Key byte</span>
      <span class="step-col-label">XOR out</span>
    </div>`;

  const rows = limited.map(s => {
    const inHex  = s.inByte.toString(16).padStart(2, '0').toUpperCase();
    const kHex   = s.kByte.toString(16).padStart(2, '0').toUpperCase();
    const ch     = (s.inByte >= 0x20 && s.inByte < 0x7F)
                   ? String.fromCharCode(s.inByte).replace(/</g,'&lt;').replace(/>/g,'&gt;')
                   : '·';
    const xorOut = (s.inByte ^ s.kByte).toString(16).padStart(2, '0').toUpperCase();

    return `<div class="step-row fade-in">
      <span class="step-idx">${s.idx}</span>
      <span class="step-char">${ch}</span>
      <span class="step-in">0x${inHex}</span>
      <span class="step-op">⊕ 0x${kHex}</span>
      <span class="step-out">0x${xorOut}</span>
    </div>`;
  });

  const overflow = steps.length > MAX_DISPLAY
    ? `<p class="steps-placeholder">… ${steps.length - MAX_DISPLAY} more bytes (truncated for display)</p>`
    : '';

  return header + rows.join('') + overflow;
}

/**
 * Builds the ROL/ROR steps HTML.
 * @param {Array} steps
 * @param {'encrypt'|'decrypt'} mode
 * @returns {string}  HTML
 */
function buildRolSteps(steps, mode) {
  if (!steps || steps.length === 0) return '<p class="steps-placeholder">— run an operation to populate —</p>';

  const MAX_DISPLAY = 128;
  const limited     = steps.slice(0, MAX_DISPLAY);
  const opLabel     = mode === 'encrypt' ? 'ROL 3' : 'ROR 3';

  const header = `
    <div class="step-row step-row-header">
      <span class="step-col-label">#</span>
      <span class="step-col-label">Char</span>
      <span class="step-col-label">XOR val</span>
      <span class="step-col-label">Op</span>
      <span class="step-col-label">Result</span>
    </div>`;

  const rows = limited.map(s => {
    const ch = (s.inByte >= 0x20 && s.inByte < 0x7F)
               ? String.fromCharCode(s.inByte).replace(/</g,'&lt;').replace(/>/g,'&gt;')
               : '·';
    let xorVal, result;
    if (mode === 'encrypt') {
      xorVal = s.xored;
      result = s.outByte;
    } else {
      // During decrypt, inByte is the ciphertext byte; ror3(inByte) = xored ^ kByte
      xorVal = s.inByte;
      result = ror3(s.inByte);
    }

    const bits = (n) => n.toString(2).padStart(8, '0');

    return `<div class="step-row fade-in">
      <span class="step-idx">${s.idx}</span>
      <span class="step-char">${ch}</span>
      <span class="step-in">${bits(xorVal)}</span>
      <span class="step-op">${opLabel}</span>
      <span class="step-out">${bits(result)}</span>
    </div>`;
  });

  const overflow = steps.length > MAX_DISPLAY
    ? `<p class="steps-placeholder">… ${steps.length - MAX_DISPLAY} more bytes (truncated for display)</p>`
    : '';

  return header + rows.join('') + overflow;
}

/* ═══════════════════════════════════════════════════════════════
   5. 32-BIT XOR CHECKSUM
   ═══════════════════════════════════════════════════════════════ */

/**
 * Computes a 32-bit XOR checksum by folding every 4 bytes.
 * @param {Uint8Array} bytes
 * @returns {number}  unsigned 32-bit integer
 */
function xorChecksum32(bytes) {
  let csum = 0;
  for (let i = 0; i < bytes.length; i++) {
    const shift = (i % 4) * 8;
    csum ^= (bytes[i] << shift);
  }
  return csum >>> 0;  // unsigned
}

/* ═══════════════════════════════════════════════════════════════
   6. SERVER BRIDGE  (fetch to Python Flask server)
   ═══════════════════════════════════════════════════════════════ */

const SERVER_URL    = 'http://127.0.0.1:5000/process';
const SERVER_PING   = 'http://127.0.0.1:5000/ping';
const FETCH_TIMEOUT = 3000;   // ms

/** Wraps fetch with a timeout. */
async function fetchWithTimeout(url, options, timeout = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const id         = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

/**
 * Returns true if the Python server is reachable.
 */
async function checkServer() {
  try {
    const resp = await fetchWithTimeout(SERVER_PING, { method: 'GET' }, 2000);
    return resp.ok;
  } catch {
    return false;
  }
}

/**
 * Calls the Python bridge.
 * @param {string} text      plaintext or base64 ciphertext
 * @param {string} key
 * @param {'encrypt'|'decrypt'} mode
 * @returns {{ result: string, engine: string }}
 */
async function callServer(text, key, mode) {
  const resp = await fetchWithTimeout(SERVER_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ text, key, mode }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Server error ${resp.status}: ${err}`);
  }

  return await resp.json();
}

/* ═══════════════════════════════════════════════════════════════
   7. UI STATE  (single source of truth for the page)
   ═══════════════════════════════════════════════════════════════ */

const state = {
  serverOnline: false,   // updated by probeServer()
  lastSteps:    [],      // last cipher steps for visualizer
  lastOutput:   null,    // Uint8Array of last output
  lastMode:     null,    // 'encrypt' | 'decrypt'
};

/* ═══════════════════════════════════════════════════════════════
   8. DOM HELPERS
   ═══════════════════════════════════════════════════════════════ */

const $ = (id) => document.getElementById(id);

function setStatus(msg, type = '') {
  const row = $('statusRow');
  row.className = 'status-row ' + type;
  if (type === 'loading') {
    row.innerHTML = `<div class="spinner"></div><span>${msg}</span>`;
  } else {
    row.textContent = msg;
  }
}

function clearStatus() {
  $('statusRow').className = 'status-row';
  $('statusRow').textContent = '';
}

/** Flash an element with a brief highlight animation. */
function flash(el) {
  el.classList.remove('flash');
  void el.offsetWidth;    // force reflow
  el.classList.add('flash');
}

/* ── Clock ───────────────────────────────────────────────────── */
function updateClock() {
  const now = new Date();
  $('clock').textContent = now.toLocaleTimeString('en-GB', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

/* ═══════════════════════════════════════════════════════════════
   9. ENGINE STATUS UI
   ═══════════════════════════════════════════════════════════════ */

function setEngineUI(online) {
  state.serverOnline = online;

  const dot      = $('engineDot');
  const label    = $('engineLabel');
  const card     = $('engineCard');
  const name     = $('engineName');
  const desc     = $('engineDesc');
  const footer   = $('footerEngine');

  dot.className  = 'pill-dot ' + (online ? 'online' : 'offline');
  card.className = 'engine-card ' + (online ? 'active-asm' : 'active-sim');

  if (online) {
    label.textContent = 'IA-32 Assembly Engine';
    name.textContent  = 'IA-32 Assembly Engine';
    desc.textContent  = 'Python bridge active · server at 127.0.0.1:5000';
    footer.textContent = 'IA-32 Assembly Engine';
  } else {
    label.textContent = 'Client Simulation';
    name.textContent  = 'Client Simulation (JS)';
    desc.textContent  = 'Server offline · rolling-XOR + ROL 3 in browser';
    footer.textContent = 'Client Simulation';
  }
}

/** Probe the server on load and periodically. */
async function probeServer() {
  const online = await checkServer();
  setEngineUI(online);
}
probeServer();
setInterval(probeServer, 10_000);   // re-check every 10 s

/* ═══════════════════════════════════════════════════════════════
   10. KEY STRENGTH UI
   ═══════════════════════════════════════════════════════════════ */

function updateKeyStrength(key) {
  if (!key) {
    $('keyStrengthBar').style.width   = '0%';
    $('keyStrengthBar').style.background = 'var(--red)';
    $('keyStrengthLabel').textContent = '—';
    updateAnalyticsKeyMeter(0, '—', {});
    return;
  }

  const { score, grade, criteria } = analyzeKey(key);
  const color = gradeColor(grade);

  // Inline bar under the key input
  $('keyStrengthBar').style.width      = score + '%';
  $('keyStrengthBar').style.background = color;
  $('keyStrengthLabel').style.color    = color;
  $('keyStrengthLabel').textContent    = grade;

  // Analytics panel meter
  updateAnalyticsKeyMeter(score, grade, criteria, color);
}

function updateAnalyticsKeyMeter(score, grade, criteria, color = '#ff3a5c') {
  $('meterFill').style.width      = score + '%';
  $('meterFill').style.background = `linear-gradient(90deg, ${color}, ${color}cc)`;
  $('meterScore').textContent     = `${score} / 100`;

  const gradeEl = $('meterGrade');
  gradeEl.textContent   = grade;
  gradeEl.style.color   = color;
  gradeEl.style.borderColor = color + '55';
  gradeEl.style.background  = color + '11';

  const checks = {
    'crit-len':   criteria.len,
    'crit-upper': criteria.upper,
    'crit-digit': criteria.digit,
    'crit-sym':   criteria.sym,
    'crit-long':  criteria.long,
  };
  const labels = {
    'crit-len':   'Min 8 characters',
    'crit-upper': 'Uppercase letter',
    'crit-digit': 'Digit',
    'crit-sym':   'Symbol',
    'crit-long':  '16+ characters (high entropy)',
  };

  for (const [id, pass] of Object.entries(checks)) {
    const el = $(id);
    if (!el) continue;
    el.className   = 'crit' + (pass ? ' pass' : '');
    el.textContent = (pass ? '✓ ' : '✗ ') + labels[id];
  }
}

/* ═══════════════════════════════════════════════════════════════
   11. VISUALIZER (hex dump + step tabs)
   ═══════════════════════════════════════════════════════════════ */

function updateVisualizer(outputBytes, steps, mode) {
  // Hex dump
  $('hexDump').innerHTML = buildHexDump(outputBytes);

  // XOR steps
  $('xorSteps').innerHTML = buildXorSteps(steps, mode);

  // ROL/ROR steps
  $('rolSteps').innerHTML = buildRolSteps(steps, mode);
}

/* ── Tab switching ───────────────────────────────────────────── */
document.querySelectorAll('.viz-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.viz-tab').forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.viz-panel').forEach(p => p.classList.remove('active'));

    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    const panel = $('tab-' + tab.dataset.tab);
    if (panel) panel.classList.add('active');
  });
});

/* ═══════════════════════════════════════════════════════════════
   12. ANALYTICS — CHECKSUM & STATS
   ═══════════════════════════════════════════════════════════════ */

function updateChecksum(bytes) {
  if (!bytes || bytes.length === 0) {
    $('checksumHex').textContent = '0x00000000';
    return;
  }
  const csum = xorChecksum32(bytes);
  $('checksumHex').textContent = '0x' + csum.toString(16).padStart(8, '0').toUpperCase();
  flash($('checksumBadge'));
}

function updateStats(bytes, timeMs, mode, engine) {
  $('statBytes').textContent  = bytes ?? '—';
  $('statTime').textContent   = timeMs !== undefined ? timeMs.toFixed(1) : '—';
  $('statOp').textContent     = mode ?? '—';
  $('statEngine').textContent = engine ?? '—';
}

/* ═══════════════════════════════════════════════════════════════
   13. CORE PROCESS FUNCTION
   ═══════════════════════════════════════════════════════════════ */

async function processData(mode) {
  const rawText = $('textInput').value;
  const key     = $('secretKey').value.trim();

  if (!rawText.trim()) { setStatus('⚠ No input text provided.', 'warn'); return; }
  if (!key)            { setStatus('⚠ Secret key is required.', 'warn'); return; }

  setStatus('Processing…', 'loading');
  $('btnEncrypt').disabled = true;
  $('btnDecrypt').disabled = true;

  const t0 = performance.now();
  let outputStr  = '';
  let outputBytes = null;
  let steps       = [];
  let engineUsed  = '';

  try {
    /* ── Try server first ── */
    if (state.serverOnline) {
      try {
        const payload = { text: rawText, key, mode };
        const json    = await callServer(rawText, key, mode);

        outputStr  = json.result ?? '';
        engineUsed = json.engine ?? 'IA-32 Assembly Engine';

        // Server returns base64-encoded result bytes
        if (json.result_bytes) {
          outputBytes = fromBase64(json.result_bytes);
        } else {
          outputBytes = new TextEncoder().encode(outputStr);
        }

        // If server provides steps, use them; otherwise fall back to JS steps
        if (json.steps && json.steps.length) {
          steps = json.steps;
        } else {
          // Compute client steps for visualizer only (don't use for final output)
          const inputBytes = mode === 'encrypt'
            ? new TextEncoder().encode(rawText)
            : fromBase64(rawText.trim());
          const kBytes = keyBytes(key);
          ({ steps } = runCipher(inputBytes, kBytes, mode));
        }

      } catch (serverErr) {
        console.warn('[Bridge] Server error, falling back to JS engine:', serverErr.message);
        setEngineUI(false);
        // Fall through to JS engine below
        engineUsed = '';
      }
    }

    /* ── JS fallback (or if server call failed) ── */
    if (!engineUsed) {
      let inputBytes;

      if (mode === 'encrypt') {
        inputBytes = new TextEncoder().encode(rawText);
      } else {
        // Expect base64-encoded ciphertext for decrypt
        try {
          inputBytes = fromBase64(rawText.trim());
        } catch {
          throw new Error('Decrypt input must be Base64-encoded ciphertext.');
        }
      }

      const kBytes  = keyBytes(key);
      const result  = runCipher(inputBytes, kBytes, mode);
      outputBytes   = result.output;
      steps         = result.steps;
      engineUsed    = 'Client JS';

      if (mode === 'encrypt') {
        outputStr = toBase64(outputBytes);
      } else {
        outputStr = new TextDecoder('utf-8', { fatal: false }).decode(outputBytes);
      }
    }

    const elapsed = performance.now() - t0;

    /* ── Update output panel ── */
    $('outputText').value = outputStr;
    $('outputMeta').textContent =
      `${outputBytes.length} bytes · ${mode} · ${engineUsed} · ${elapsed.toFixed(1)} ms`;

    /* ── Visualizer ── */
    state.lastSteps  = steps;
    state.lastOutput = outputBytes;
    state.lastMode   = mode;
    updateVisualizer(outputBytes, steps, mode);

    /* ── Analytics ── */
    updateChecksum(outputBytes);
    updateStats(outputBytes.length, elapsed, mode.toUpperCase(), engineUsed);

    setStatus(`✓ ${mode === 'encrypt' ? 'Encrypted' : 'Decrypted'} ${outputBytes.length} bytes`, 'success');

  } catch (err) {
    setStatus('✗ ' + err.message, 'error');
    console.error('[CryptoVault]', err);
  } finally {
    $('btnEncrypt').disabled = false;
    $('btnDecrypt').disabled = false;
  }
}

/* ═══════════════════════════════════════════════════════════════
   14. EVENT WIRING
   ═══════════════════════════════════════════════════════════════ */

/* Encrypt / Decrypt buttons */
$('btnEncrypt').addEventListener('click', () => processData('encrypt'));
$('btnDecrypt').addEventListener('click', () => processData('decrypt'));

/* Clear */
$('btnClear').addEventListener('click', () => {
  $('textInput').value  = '';
  $('secretKey').value  = '';
  $('outputText').value = '';
  $('outputMeta').textContent = '';
  $('dzFilename').textContent = '';
  $('hexDump').innerHTML  = '— run an operation to populate —';
  $('xorSteps').innerHTML = '<p class="steps-placeholder">— run an operation to populate —</p>';
  $('rolSteps').innerHTML = '<p class="steps-placeholder">— run an operation to populate —</p>';
  updateChecksum(null);
  updateStats();
  updateKeyStrength('');
  clearStatus();
  state.lastSteps  = [];
  state.lastOutput = null;
});

/* Copy output */
$('btnCopy').addEventListener('click', async () => {
  const text = $('outputText').value;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    $('btnCopy').classList.add('copied');
    $('btnCopy').textContent = '✓ Copied';
    setTimeout(() => {
      $('btnCopy').classList.remove('copied');
      $('btnCopy').textContent = '⎗ Copy';
    }, 1800);
  } catch {
    // Fallback for non-secure contexts
    $('outputText').select();
    document.execCommand('copy');
  }
});

/* Show / hide key */
$('toggleKey').addEventListener('click', () => {
  const inp = $('secretKey');
  const isPassword = inp.type === 'password';
  inp.type = isPassword ? 'text' : 'password';
  $('eyeIcon').style.display    = isPassword ? 'none'  : '';
  $('eyeOffIcon').style.display = isPassword ? ''      : 'none';
});

/* Key strength — live update */
$('secretKey').addEventListener('input', () => {
  updateKeyStrength($('secretKey').value);
});

/* Keyboard shortcut: Ctrl+Enter → Encrypt */
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'Enter') {
    e.preventDefault();
    processData('encrypt');
  }
  if (e.ctrlKey && e.shiftKey && e.key === 'Enter') {
    e.preventDefault();
    processData('decrypt');
  }
});

/* ── File drop zone ──────────────────────────────────────────── */
const dropzone  = $('dropzone');
const fileInput = $('fileInput');

dropzone.addEventListener('click', () => fileInput.click());

dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('drag-over');
});

dropzone.addEventListener('dragleave', () => {
  dropzone.classList.remove('drag-over');
});

dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('drag-over');
  const file = e.dataTransfer?.files?.[0];
  if (file) loadFile(file);
});

fileInput.addEventListener('change', () => {
  const file = fileInput.files?.[0];
  if (file) loadFile(file);
});

function loadFile(file) {
  if (!file.name.endsWith('.txt')) {
    setStatus('⚠ Only .txt files are supported.', 'warn');
    return;
  }
  const reader = new FileReader();
  reader.onload  = (e) => {
    $('textInput').value    = e.target.result;
    $('dzFilename').textContent = `✓ ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    setStatus(`Loaded: ${file.name}`, 'success');
  };
  reader.onerror = () => setStatus('✗ Failed to read file.', 'error');
  reader.readAsText(file, 'utf-8');
}

/* ═══════════════════════════════════════════════════════════════
   15. INIT
   ═══════════════════════════════════════════════════════════════ */
(function init() {
  // Seed UI with empty state
  updateKeyStrength('');
  updateChecksum(null);
  updateStats();
  setStatus('Ready · Ctrl+Enter to encrypt, Ctrl+Shift+Enter to decrypt', '');
})();
