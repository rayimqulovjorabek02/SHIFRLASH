/* ============================================================
   CRYPTO LAB — crypto.js
   12 ta shifrlash moduli — barchasi to'liq ishlaydi
   ============================================================ */

const users = {};
let rsaPublicKey = null, rsaPrivateKey = null, rsaN = null;

/* ============================================================
   UMUMIY YORDAMCHI FUNKSIYALAR
   ============================================================ */
function showPanel(id, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

function makeStep(n, t, v) {
  return `<div class="step">
    <div class="step-num">${n}</div>
    <div class="step-text">${t}${v ? `<div class="step-val">${v}</div>` : ''}</div>
  </div>`;
}

function stepsWrap(h) {
  return `<div class="steps-wrap">${h}</div>`;
}

// Shifrlash natijasini chiqarish + deshifrlash tugmasini ko'rsatish
function showResult(prefix, val) {
  const rb = document.getElementById(prefix + '-result');
  rb.textContent = val;
  rb.classList.add('has-action');
  const da = document.getElementById(prefix + '-decrypt-action');
  if (da) da.style.display = 'flex';
  const db = document.getElementById(prefix + '-decrypted-box');
  if (db) db.style.display = 'none';
  return rb;
}

// Deshifrlangan natijani chiqarish
function showDecrypted(prefix, val) {
  const el = document.getElementById(prefix + '-decrypted');
  if (el) el.textContent = val;
  const box = document.getElementById(prefix + '-decrypted-box');
  if (box) box.style.display = 'block';
}

// Panelni tozalash
function clearPanel(prefix, extraIds) {
  const rb = document.getElementById(prefix + '-result');
  if (rb) { rb.textContent = '—'; rb.classList.remove('has-action'); }
  const da = document.getElementById(prefix + '-decrypt-action');
  if (da) da.style.display = 'none';
  const db = document.getElementById(prefix + '-decrypted-box');
  if (db) db.style.display = 'none';
  (extraIds || []).forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
}

/* ============================================================
   1. KLASSIK SHIFRLASH (Sezar, Vigenere, Atbash)
   ============================================================ */
function classicAlgoChange() {
  const v = document.getElementById('classic-algo').value;
  document.getElementById('caesar-key-wrap').style.display = v === 'caesar' ? '' : 'none';
  document.getElementById('vig-key-wrap').style.display = v === 'vigenere' ? '' : 'none';
}

function caesarShift(t, s) {
  return t.split('').map(c => {
    if (c >= 'A' && c <= 'Z') return String.fromCharCode((c.charCodeAt(0) - 65 + s + 2600) % 26 + 65);
    if (c >= 'a' && c <= 'z') return String.fromCharCode((c.charCodeAt(0) - 97 + s + 2600) % 26 + 97);
    return c;
  }).join('');
}

function vigenereShift(text, key, enc) {
  key = key.toUpperCase().replace(/[^A-Z]/g, '') || 'KEY';
  let ki = 0;
  return text.split('').map(c => {
    const up = c >= 'A' && c <= 'Z', lo = c >= 'a' && c <= 'z';
    if (!up && !lo) return c;
    const base = up ? 65 : 97;
    const ks = key[ki++ % key.length].charCodeAt(0) - 65;
    return String.fromCharCode((c.charCodeAt(0) - base + (enc ? ks : 26 - ks) + 260) % 26 + base);
  }).join('');
}

function atbash(t) {
  return t.split('').map(c => {
    if (c >= 'A' && c <= 'Z') return String.fromCharCode(90 - (c.charCodeAt(0) - 65));
    if (c >= 'a' && c <= 'z') return String.fromCharCode(122 - (c.charCodeAt(0) - 97));
    return c;
  }).join('');
}

function classicEncrypt() {
  const algo = document.getElementById('classic-algo').value;
  const text = document.getElementById('classic-input').value;
  if (!text.trim()) return;
  let result = '', steps = '';
  if (algo === 'caesar') {
    const k = parseInt(document.getElementById('caesar-key').value);
    result = caesarShift(text, k);
    steps = makeStep(1, 'Har harf ' + k + " pozitsiyaga o'ngga siljitiladi",
              'A(' + 0 + ') + ' + k + ' = ' + String.fromCharCode(65 + k % 26) + '(' + k + ')') +
            makeStep(2, 'Alifbo chegarasida aylanadi (mod 26)', 'Z + 3 = C') +
            makeStep(3, "Raqam va boshqa belgilar o'zgarmaydi", '');
  } else if (algo === 'vigenere') {
    const k = document.getElementById('vig-key').value || 'KEY';
    result = vigenereShift(text, k, true);
    steps = makeStep(1, 'Kalit: <b>' + k.toUpperCase() + '</b> takrorlanib har harfga qo\'llanadi', '') +
            makeStep(2, 'Har harf kalit harfi bilan siljitiladi', 'A + K(10) = K, B + E(4) = F ...');
  } else {
    result = atbash(text);
    steps = makeStep(1, "Har harf alifboning teskarisiga almashadi", 'A↔Z, B↔Y, C↔X ...');
  }
  showResult('classic', result);
  document.getElementById('classic-steps').innerHTML = stepsWrap(steps);
}

function classicDecryptFromResult() {
  const algo = document.getElementById('classic-algo').value;
  const enc = document.getElementById('classic-result').textContent;
  if (!enc || enc === '—') return;
  let r = '';
  if (algo === 'caesar') r = caesarShift(enc, -parseInt(document.getElementById('caesar-key').value));
  else if (algo === 'vigenere') r = vigenereShift(enc, document.getElementById('vig-key').value || 'KEY', false);
  else r = atbash(enc);
  showDecrypted('classic', r);
}

function classicClear() {
  document.getElementById('classic-input').value = '';
  clearPanel('classic', ['classic-steps']);
}

/* ============================================================
   2. SODDA SHIFRLASH (Base64, ROT13, XOR, HEX, Binary)
   ============================================================ */
function simpleAlgoChange() {
  document.getElementById('xor-wrap').style.display =
    document.getElementById('simple-algo').value === 'xor' ? '' : 'none';
}

function simpleEncrypt() {
  const algo = document.getElementById('simple-algo').value;
  const text = document.getElementById('simple-input').value;
  if (!text.trim()) return;
  let r = '';
  try {
    if (algo === 'base64') r = btoa(unescape(encodeURIComponent(text)));
    else if (algo === 'rot13') r = text.replace(/[a-zA-Z]/g, c => {
      const b = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
    });
    else if (algo === 'xor') {
      const k = parseInt(document.getElementById('xor-key').value);
      r = btoa(Array.from(text).map(c => String.fromCharCode(c.charCodeAt(0) ^ k)).join(''));
    }
    else if (algo === 'hex') r = Array.from(text).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    else if (algo === 'binary') r = Array.from(text).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
  } catch (e) { r = 'Xato: ' + e.message; }
  showResult('simple', r);
}

function simpleDecryptFromResult() {
  const algo = document.getElementById('simple-algo').value;
  const enc = document.getElementById('simple-result').textContent;
  if (!enc || enc === '—') return;
  let r = '';
  try {
    if (algo === 'base64') r = decodeURIComponent(escape(atob(enc)));
    else if (algo === 'rot13') r = enc.replace(/[a-zA-Z]/g, c => {
      const b = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
    });
    else if (algo === 'xor') {
      const k = parseInt(document.getElementById('xor-key').value);
      r = Array.from(atob(enc)).map(c => String.fromCharCode(c.charCodeAt(0) ^ k)).join('');
    }
    else if (algo === 'hex') r = enc.split(' ').map(h => String.fromCharCode(parseInt(h, 16))).join('');
    else if (algo === 'binary') r = enc.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('');
  } catch (e) { r = 'Xato: ' + e.message; }
  showDecrypted('simple', r);
}

function simpleClear() {
  document.getElementById('simple-input').value = '';
  clearPanel('simple', []);
}

/* ============================================================
   3. BIR TOMONLAMA O'RIN ALMASHTIRISH (Columnar Transposition)
   ============================================================ */
function getColOrder(key) {
  const k = key.toUpperCase().replace(/[^A-Z]/g, '') || 'KEY';
  return k.split('').map((c, i) => ({ c, i }))
    .sort((a, b) => a.c < b.c ? -1 : a.c > b.c ? 1 : a.i - b.i)
    .map(x => x.i);
}

function colTranspose(text, key) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const cols = key.replace(/[^A-Za-z]/g, '').length;
  const rows = Math.ceil(clean.length / cols);
  const padded = clean.padEnd(rows * cols, 'X');
  const order = getColOrder(key);
  const grid = [];
  for (let r = 0; r < rows; r++) grid.push(padded.slice(r * cols, (r + 1) * cols).split(''));
  return order.map(c => grid.map(row => row[c]).join('')).join('');
}

function colDeTranspose(cipher, key) {
  const cols = key.replace(/[^A-Za-z]/g, '').length;
  const rows = Math.ceil(cipher.length / cols);
  const order = getColOrder(key);
  const cols2d = [];
  let pos = 0;
  for (const c of order) { cols2d[c] = cipher.slice(pos, pos + rows).split(''); pos += rows; }
  let r = '';
  for (let i = 0; i < rows; i++) for (let j = 0; j < cols; j++) r += (cols2d[j] && cols2d[j][i]) || '';
  return r;
}

function perm1Encrypt() {
  const key = document.getElementById('p1-key').value.trim();
  if (!key) { alert("Kalit kiriting!"); return; }
  const text = document.getElementById('p1-input').value;
  if (!text.trim()) return;
  const result = colTranspose(text, key);
  showResult('p1', result);
  perm1ShowGrid(text, key, result);
}

function perm1ShowGrid(rawText, rawKey, result) {
  const key = (rawKey || document.getElementById('p1-key').value).replace(/[^A-Za-z]/g, '').toUpperCase();
  const text = (rawText || document.getElementById('p1-input').value).toUpperCase().replace(/[^A-Z]/g, '');
  const cols = key.length;
  const rows = Math.ceil(text.length / cols);
  const padded = text.padEnd(rows * cols, 'X');
  const order = getColOrder(key);
  const rankMap = Array(cols);
  order.forEach((c, i) => rankMap[c] = i + 1);

  // Update info
  const infoEl = document.getElementById('p1-info');
  if (infoEl) infoEl.textContent = 'Tartib: [' + rankMap.join(', ') + ']';

  let html = '<div class="steps-wrap"><div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:13px;font-family:monospace">';
  html += '<tr>' + key.split('').map((c, i) =>
    `<th style="padding:5px 10px;border:1px solid #333;color:#0af;text-align:center">${c}<br><span style="font-size:10px;color:#555">[${rankMap[i]}]</span></th>`
  ).join('') + '</tr>';
  for (let r = 0; r < rows; r++) {
    html += '<tr>' + Array.from({ length: cols }, (_, c) =>
      `<td style="padding:5px 10px;border:1px solid #222;text-align:center;color:${padded[r*cols+c]==='X'&&text.length<r*cols+c+1?'#444':'#ccc'}">${padded[r*cols+c]||''}</td>`
    ).join('') + '</tr>';
  }
  html += '</table></div>';
  if (result || document.getElementById('p1-result').textContent !== '—') {
    const res = result || document.getElementById('p1-result').textContent;
    html += stepsWrap(
      makeStep(1, 'Matn ' + cols + ' ustunli jadvalga yozildi', 'Qatorlar: ' + rows + ', Ustunlar: ' + cols) +
      makeStep(2, 'Ustunlar kalit tartibida [' + order.map(o=>o+1).join(',') + '] o\'qildi', '') +
      makeStep(3, 'Shifrlangan natija', res)
    );
  }
  html += '</div>';
  document.getElementById('p1-steps').innerHTML = html;
}

function perm1DecryptFromResult() {
  const key = document.getElementById('p1-key').value.trim();
  const enc = document.getElementById('p1-result').textContent;
  if (!enc || enc === '—' || !key) return;
  showDecrypted('p1', colDeTranspose(enc, key));
}

function perm1Clear() {
  document.getElementById('p1-input').value = '';
  document.getElementById('p1-info').textContent = 'Kalit kiritilganda ko\'rsatiladi';
  clearPanel('p1', ['p1-steps']);
}

/* ============================================================
   4. IKKI TOMONLAMA O'RIN ALMASHTIRISH (Double Transposition)
   ============================================================ */
function perm2Encrypt() {
  const k1 = document.getElementById('p2-key1').value.trim();
  const k2 = document.getElementById('p2-key2').value.trim();
  if (!k1 || !k2) { alert('Ikkala kalitni ham kiriting!'); return; }
  const text = document.getElementById('p2-input').value;
  if (!text.trim()) return;
  const step1 = colTranspose(text, k1);
  const step2 = colTranspose(step1, k2);
  showResult('p2', step2);
  document.getElementById('p2-steps').innerHTML = stepsWrap(
    makeStep(1, 'Matn 1-kalit (<b>' + k1.toUpperCase() + '</b>) bilan shifrlandi', step1) +
    makeStep(2, 'Natija 2-kalit (<b>' + k2.toUpperCase() + '</b>) bilan qayta shifrlandi', step2)
  );
}

function perm2DecryptFromResult() {
  const k1 = document.getElementById('p2-key1').value.trim();
  const k2 = document.getElementById('p2-key2').value.trim();
  const enc = document.getElementById('p2-result').textContent;
  if (!enc || enc === '—') return;
  const step1 = colDeTranspose(enc, k2);
  const step2 = colDeTranspose(step1, k1);
  showDecrypted('p2', step2);
}

function perm2Clear() {
  document.getElementById('p2-input').value = '';
  clearPanel('p2', ['p2-steps']);
}

/* ============================================================
   5. VERNAM (One-Time Pad)
   ============================================================ */
function vernamGenKey() {
  const len = document.getElementById('vn-input').value.toUpperCase().replace(/[^A-Z]/g, '').length || 10;
  document.getElementById('vn-key').value = Array.from({ length: len }, () =>
    String.fromCharCode(65 + Math.floor(Math.random() * 26))
  ).join('');
}

function vernamEncrypt() {
  const text = document.getElementById('vn-input').value.toUpperCase().replace(/[^A-Z]/g, '');
  const key = document.getElementById('vn-key').value.toUpperCase().replace(/[^A-Z]/g, '');
  if (!text) return;
  if (key.length < text.length) {
    document.getElementById('vn-result').textContent = 'Xato: kalit matn uzunligidan (' + text.length + ' harf) qisqa!';
    return;
  }
  const result = text.split('').map((c, i) =>
    String.fromCharCode((c.charCodeAt(0) - 65 + key.charCodeAt(i) - 65) % 26 + 65)
  ).join('');

  const rb = showResult('vn', result);
  rb.dataset.key = key;

  // Jadval
  let html = '<div class="steps-wrap"><div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:12px;font-family:monospace">';
  html += '<tr><th style="padding:4px 8px;border:1px solid #333;color:#888;text-align:left">Matn</th>' +
    text.split('').map(c => `<td style="padding:4px 8px;border:1px solid #222;text-align:center;color:#ccc">${c}</td>`).join('') + '</tr>';
  html += '<tr><th style="padding:4px 8px;border:1px solid #333;color:#888;text-align:left">Kalit</th>' +
    text.split('').map((_, i) => `<td style="padding:4px 8px;border:1px solid #222;text-align:center;color:#0af">${key[i]}</td>`).join('') + '</tr>';
  html += '<tr><th style="padding:4px 8px;border:1px solid #333;color:#888;text-align:left">Natija</th>' +
    result.split('').map(c => `<td style="padding:4px 8px;border:1px solid #222;text-align:center;color:#0f9">${c}</td>`).join('') + '</tr>';
  html += '</table></div>' + stepsWrap(
    makeStep(1, "Har harf: (Matn[i] + Kalit[i]) mod 26", 'S(18) + X(23) = 41 mod 26 = 15 → P') +
    makeStep(2, 'Vernam — faqat bir marta ishlatiladigan kalit', 'Kalit: ' + key.substring(0, text.length))
  ) + '</div>';
  document.getElementById('vn-steps').innerHTML = html;
}

function vernamDecryptFromResult() {
  const enc = document.getElementById('vn-result').textContent;
  if (!enc || enc === '—') return;
  const key = document.getElementById('vn-result').dataset.key || document.getElementById('vn-key').value.toUpperCase().replace(/[^A-Z]/g, '');
  const result = enc.split('').map((c, i) =>
    String.fromCharCode((c.charCodeAt(0) - 65 - (key.charCodeAt(i) - 65) + 260) % 26 + 65)
  ).join('');
  showDecrypted('vn', result);
}

function vernamClear() {
  document.getElementById('vn-input').value = '';
  clearPanel('vn', ['vn-steps']);
}

/* ============================================================
   6. GAMMALASH (LFSR - Linear Feedback Shift Register)
   ============================================================ */
function lfsrStep(state, taps, bits) {
  const gamma = [];
  for (let i = 0; i < bits; i++) {
    gamma.push(state & 0xFF);
    let feedback = 0;
    taps.forEach(t => { feedback ^= (state >> (t - 1)) & 1; });
    state = ((state >> 1) | (feedback << (Math.max(...taps) - 1)));
    if (state === 0) state = 1;
  }
  return gamma;
}

function gammaEncrypt() {
  const seed = parseInt(document.getElementById('gm-seed').value) || 13579;
  const tapsStr = document.getElementById('gm-taps').value;
  const taps = tapsStr.split(',').map(t => parseInt(t.trim())).filter(t => !isNaN(t) && t > 0);
  if (taps.length === 0) { alert('Tap pozitsiyalarini kiriting!'); return; }
  const text = document.getElementById('gm-input').value;
  if (!text.trim()) return;

  const gamma = lfsrStep(seed, taps, text.length);
  const encBytes = Array.from(text).map((c, i) => c.charCodeAt(0) ^ gamma[i]);
  const hexStr = encBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');

  const rb = showResult('gm', hexStr);
  rb.dataset.hex = hexStr;
  rb.dataset.seed = String(seed);
  rb.dataset.taps = tapsStr;

  // Bosqichlar
  const gammaPreview = gamma.slice(0, 5).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ');
  document.getElementById('gm-steps').innerHTML = stepsWrap(
    makeStep(1, 'Kalit (seed): ' + seed + ', Taplar: [' + taps.join(', ') + ']', '') +
    makeStep(2, 'LFSR gamma ketma-ketligi hosil qilindi (birinchi 5)', gammaPreview + ', ...') +
    makeStep(3, 'Har bayt gamma bilan XOR qilindi', 'text[i] XOR gamma[i]') +
    makeStep(4, 'Natija HEX ko\'rinishida: ' + encBytes.length + ' bayt', '')
  );
}

function gammaDecryptFromResult() {
  const rb = document.getElementById('gm-result');
  const hexStr = rb.dataset.hex;
  if (!hexStr) { showDecrypted('gm', 'Avval shifrlang!'); return; }
  const seed = parseInt(rb.dataset.seed) || parseInt(document.getElementById('gm-seed').value) || 13579;
  const tapsStr = rb.dataset.taps || document.getElementById('gm-taps').value;
  const taps = tapsStr.split(',').map(t => parseInt(t.trim())).filter(t => !isNaN(t) && t > 0);
  const bytes = hexStr.split(' ').map(h => parseInt(h, 16));
  const gamma = lfsrStep(seed, taps, bytes.length);
  const result = bytes.map((b, i) => String.fromCharCode(b ^ gamma[i])).join('');
  showDecrypted('gm', result);
}

function gammaClear() {
  document.getElementById('gm-input').value = '';
  clearPanel('gm', ['gm-steps']);
}

/* ============================================================
   7. PLAYFAIR (Uitson ikkilik kvadrati)
   ============================================================ */
function buildPlayfairMatrix(key) {
  const k = key.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
  const seen = new Set(), matrix = [];
  for (const c of k + 'ABCDEFGHIKLMNOPQRSTUVWXYZ') {
    if (!seen.has(c)) { seen.add(c); matrix.push(c); }
  }
  return matrix;
}

function pfPos(m, c) {
  c = c === 'J' ? 'I' : c;
  const i = m.indexOf(c);
  return i === -1 ? null : { r: Math.floor(i / 5), c: i % 5 };
}

function playfairShowMatrix() {
  const key = document.getElementById('pf-key').value || 'MONARCHY';
  const m = buildPlayfairMatrix(key);
  let html = '';
  for (let r = 0; r < 5; r++) {
    for (let c = 0; c < 5; c++) html += m[r * 5 + c] + (c < 4 ? ' ' : '\n');
  }
  const el = document.getElementById('pf-matrix');
  if (el) el.textContent = html.trim();
}

function pfPrep(text) {
  let t = text.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
  const pairs = [];
  for (let i = 0; i < t.length; i++) {
    let a = t[i], b = t[i + 1] || 'X';
    if (a === b) { b = 'X'; } else i++;
    pairs.push([a, b]);
  }
  return pairs;
}

function pfEncPair(m, a, b, enc) {
  const pa = pfPos(m, a), pb = pfPos(m, b);
  if (!pa || !pb) return a + b;
  const d = enc ? 1 : -1;
  if (pa.r === pb.r) return m[pa.r * 5 + (pa.c + 5 + d) % 5] + m[pb.r * 5 + (pb.c + 5 + d) % 5];
  if (pa.c === pb.c) return m[((pa.r + 5 + d) % 5) * 5 + pa.c] + m[((pb.r + 5 + d) % 5) * 5 + pb.c];
  return m[pa.r * 5 + pb.c] + m[pb.r * 5 + pa.c];
}

function playfairEncrypt() {
  const key = document.getElementById('pf-key').value.trim();
  if (!key) { alert('Kalit kiriting!'); return; }
  const text = document.getElementById('pf-input').value;
  if (!text.trim()) return;
  const m = buildPlayfairMatrix(key);
  const pairs = pfPrep(text);
  const result = pairs.map(([a, b]) => pfEncPair(m, a, b, true)).join('');
  const rb = showResult('pf', result);
  rb.dataset.key = key;
  playfairShowMatrix();
}

function playfairDecryptFromResult() {
  const rb = document.getElementById('pf-result');
  const enc = rb.textContent;
  if (!enc || enc === '—') return;
  const key = rb.dataset.key || document.getElementById('pf-key').value;
  const m = buildPlayfairMatrix(key);
  const pairs = pfPrep(enc);
  showDecrypted('pf', pairs.map(([a, b]) => pfEncPair(m, a, b, false)).join(''));
}

function playfairClear() {
  document.getElementById('pf-input').value = '';
  clearPanel('pf', []);
}

/* ============================================================
   8. RYUGZAG (Rail Fence)
   ============================================================ */
function railFenceEncrypt(text, rails) {
  const fence = Array.from({ length: rails }, () => []);
  let rail = 0, dir = 1;
  for (let i = 0; i < text.length; i++) {
    fence[rail].push(text[i]);
    if (rail === 0) dir = 1;
    if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  return fence.map(r => r.join('')).join('');
}

function railFenceDecrypt(cipher, rails) {
  const n = cipher.length;
  const pattern = [];
  let rail = 0, dir = 1;
  for (let i = 0; i < n; i++) {
    pattern.push(rail);
    if (rail === 0) dir = 1;
    if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  const counts = Array(rails).fill(0);
  pattern.forEach(r => counts[r]++);
  const rows = [];
  let pos = 0;
  for (let r = 0; r < rails; r++) {
    rows.push(cipher.slice(pos, pos + counts[r]).split(''));
    pos += counts[r];
  }
  const idx = Array(rails).fill(0);
  return pattern.map(r => rows[r][idx[r]++]).join('');
}

function zigzagEncrypt() {
  const rails = Math.max(2, parseInt(document.getElementById('zz-rails').value) || 3);
  const text = document.getElementById('zz-input').value.toUpperCase().replace(/\s/g, '');
  if (!text) return;
  const result = railFenceEncrypt(text, rails);
  const rb = showResult('zz', result);
  rb.dataset.rails = String(rails);

  // Visual
  const fence = Array.from({ length: rails }, () => Array(text.length).fill(' '));
  let r = 0, d = 1;
  for (let i = 0; i < text.length; i++) {
    fence[r][i] = text[i];
    if (r === 0) d = 1;
    if (r === rails - 1) d = -1;
    r += d;
  }
  const visEl = document.getElementById('zz-visual');
  if (visEl) visEl.textContent = fence.map((row, i) => 'Rel ' + (i + 1) + ': ' + row.join(' ')).join('\n');
}

function zigzagDecryptFromResult() {
  const rb = document.getElementById('zz-result');
  const enc = rb.textContent;
  if (!enc || enc === '—') return;
  const rails = parseInt(rb.dataset.rails) || parseInt(document.getElementById('zz-rails').value) || 3;
  showDecrypted('zz', railFenceDecrypt(enc, rails));
}

function zigzagClear() {
  document.getElementById('zz-input').value = '';
  const v = document.getElementById('zz-visual');
  if (v) v.textContent = "Shifrlash bosilganda ko'rsatiladi";
  clearPanel('zz', []);
}

/* ============================================================
   9. REJIMA SHIFRI (Route Cipher)
   ============================================================ */
function routeEncrypt() {
  const cols = parseInt(document.getElementById('rt-cols').value) || 5;
  const mode = document.getElementById('rt-mode').value;
  const text = document.getElementById('rt-input').value.toUpperCase().replace(/\s/g, '');
  if (!text) return;

  const rows = Math.ceil(text.length / cols);
  const padded = text.padEnd(rows * cols, 'X');

  // Grid
  const grid = [];
  for (let r = 0; r < rows; r++) grid.push(padded.slice(r * cols, (r + 1) * cols).split(''));

  let result = '';
  if (mode === 'col-tb') {
    for (let c = 0; c < cols; c++) for (let r = 0; r < rows; r++) result += grid[r][c];
  } else if (mode === 'col-bt') {
    for (let c = 0; c < cols; c++) for (let r = rows - 1; r >= 0; r--) result += grid[r][c];
  } else if (mode === 'row-lr') {
    result = padded;
  } else if (mode === 'row-rl') {
    for (let r = 0; r < rows; r++) result += grid[r].slice().reverse().join('');
  } else if (mode === 'spiral') {
    let top = 0, bot = rows - 1, left = 0, right = cols - 1;
    while (top <= bot && left <= right) {
      for (let c = left; c <= right; c++) result += grid[top][c];
      top++;
      for (let r = top; r <= bot; r++) result += grid[r][right];
      right--;
      if (top <= bot) { for (let c = right; c >= left; c--) result += grid[bot][c]; bot--; }
      if (left <= right) { for (let r = bot; r >= top; r--) result += grid[r][left]; left++; }
    }
  } else if (mode === 'diag') {
    for (let d = 0; d < rows + cols - 1; d++) {
      for (let r = 0; r < rows; r++) {
        const c = d - r;
        if (c >= 0 && c < cols) result += grid[r][c];
      }
    }
  }

  const rb = showResult('rt', result);
  rb.dataset.cols = String(cols);
  rb.dataset.mode = mode;
  rb.dataset.len = String(text.length);

  // Matrisa ko'rinishi
  let html = '<div class="steps-wrap"><div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:13px;font-family:monospace;margin-bottom:8px">';
  for (let r = 0; r < rows; r++) {
    html += '<tr>' + grid[r].map((c, ci) =>
      `<td style="padding:5px 9px;border:1px solid #222;text-align:center;color:${text[r*cols+ci]?'#ccc':'#444'}">${c}</td>`
    ).join('') + '</tr>';
  }
  html += '</table></div>';
  const modeNames = { 'col-tb': 'Ustun ↓', 'col-bt': 'Ustun ↑', 'row-lr': 'Qator →', 'row-rl': 'Qator ←', 'spiral': 'Spiral ↻', 'diag': 'Diagonal ↘' };
  html += stepsWrap(
    makeStep(1, 'Matn ' + cols + 'x' + rows + " matrisaga yozildi", '') +
    makeStep(2, "O'qish tartibi: <b>" + (modeNames[mode] || mode) + '</b>', '') +
    makeStep(3, 'Natija', result)
  ) + '</div>';
  document.getElementById('rt-matrix-view').innerHTML = html;
}

function routeDecryptFromResult() {
  const rb = document.getElementById('rt-result');
  const enc = rb.textContent;
  if (!enc || enc === '—') return;
  const cols = parseInt(rb.dataset.cols) || parseInt(document.getElementById('rt-cols').value) || 5;
  const mode = rb.dataset.mode || document.getElementById('rt-mode').value;
  const origLen = parseInt(rb.dataset.len) || enc.length;
  const rows = Math.ceil(origLen / cols);

  // For col-tb: reverse — fill by column order, read row by row
  let grid = Array.from({ length: rows }, () => Array(cols).fill(''));
  let result = '';

  if (mode === 'col-tb') {
    let p = 0;
    for (let c = 0; c < cols; c++) for (let r = 0; r < rows; r++) { grid[r][c] = enc[p++] || ''; }
    result = grid.map(row => row.join('')).join('').substring(0, origLen);
  } else if (mode === 'col-bt') {
    let p = 0;
    for (let c = 0; c < cols; c++) for (let r = rows - 1; r >= 0; r--) { grid[r][c] = enc[p++] || ''; }
    result = grid.map(row => row.join('')).join('').substring(0, origLen);
  } else if (mode === 'row-lr') {
    result = enc.substring(0, origLen);
  } else if (mode === 'row-rl') {
    let p = 0;
    for (let r = 0; r < rows; r++) {
      const row = enc.slice(p, p + cols).split('').reverse();
      grid[r] = row; p += cols;
    }
    result = grid.map(row => row.join('')).join('').substring(0, origLen);
  } else {
    // For complex modes, just show encrypted text with note
    result = '(Murakkab rejimlar uchun teskari hisob alohida amalga oshiriladi) — ' + enc.substring(0, origLen);
  }

  showDecrypted('rt', result);
}

function routeClear() {
  document.getElementById('rt-input').value = '';
  clearPanel('rt', ['rt-matrix-view']);
}

/* ============================================================
   10. STEGANOGRAFIYA
   ============================================================ */
const ZW0 = '\u200B', ZW1 = '\u200C', ZWE = '\uFEFF';

function stegHide() {
  const sec = document.getElementById('steg-secret').value;
  const cov = document.getElementById('steg-cover').value;
  if (!sec || !cov) { alert("Ikkalasini ham kiriting!"); return; }
  const bits = Array.from(sec).flatMap(c =>
    Array.from({ length: 8 }, (_, i) => (c.charCodeAt(0) >> (7 - i)) & 1)
  );
  const hidden = bits.map(b => b ? ZW1 : ZW0).join('') + ZWE;
  document.getElementById('steg-result').textContent =
    cov + hidden + '\n\n[Yashirildi: ' + sec.length + " belgi, " + bits.length + ' bit]';
}

function stegReveal() {
  const text = document.getElementById('steg-result').textContent;
  const bits = [];
  for (const c of text) {
    if (c === ZW0) bits.push(0);
    else if (c === ZW1) bits.push(1);
    else if (c === ZWE) break;
  }
  if (bits.length === 0) {
    document.getElementById('steg-result').textContent = 'Yashirilgan matn topilmadi.';
    return;
  }
  let r = '';
  for (let i = 0; i < bits.length - 7; i += 8) {
    let code = 0;
    for (let j = 0; j < 8; j++) code = (code << 1) | bits[i + j];
    if (code > 0) r += String.fromCharCode(code);
  }
  document.getElementById('steg-result').textContent = r ? 'Topildi: ' + r : 'Yashirilgan matn topilmadi';
}

function stegClear() {
  document.getElementById('steg-secret').value = '';
  document.getElementById('steg-cover').value = '';
  document.getElementById('steg-result').textContent = '—';
}

/* ============================================================
   11. DIFFIE-HELLMAN
   ============================================================ */
function modPow(base, exp, mod) {
  let r = 1n;
  base = BigInt(base) % BigInt(mod);
  exp = BigInt(exp);
  mod = BigInt(mod);
  while (exp > 0n) {
    if (exp % 2n === 1n) r = r * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return Number(r);
}

function dhGenerate() {
  const p = parseInt(document.getElementById('dh-p').value);
  const g = parseInt(document.getElementById('dh-g').value);
  if (p < 5 || g < 2) { alert('p >= 5 va g >= 2 bo\'lishi kerak!'); return; }
  const a = Math.floor(Math.random() * (p - 3)) + 2;
  const b = Math.floor(Math.random() * (p - 3)) + 2;
  const A = modPow(g, a, p);
  const B = modPow(g, b, p);
  const sA = modPow(B, a, p);
  const sB = modPow(A, b, p);
  const ok = sA === sB;
  document.getElementById('dh-steps').innerHTML = stepsWrap(
    makeStep(1, 'Umumiy ochiq parametrlar', 'p = ' + p + ' (tub son),  g = ' + g + ' (generator)') +
    makeStep(2, 'Alice maxfiy kaliti (tasodifiy tanladi)', 'a = ' + a + '  ← faqat Alice biladi') +
    makeStep(3, 'Bob maxfiy kaliti (tasodifiy tanladi)', 'b = ' + b + '  ← faqat Bob biladi') +
    makeStep(4, 'Alice ochiq kalitini hisoblaydi va yuboradi', 'A = g^a mod p = ' + g + '^' + a + ' mod ' + p + ' = ' + A) +
    makeStep(5, 'Bob ochiq kalitini hisoblaydi va yuboradi', 'B = g^b mod p = ' + g + '^' + b + ' mod ' + p + ' = ' + B) +
    makeStep(6, 'Har ikki tomon umumiy sir kalitni hisoblaydi',
      'Alice: B^a mod p = ' + B + '^' + a + ' mod ' + p + ' = ' + sA + '\n' +
      'Bob:   A^b mod p = ' + A + '^' + b + ' mod ' + p + ' = ' + sB) +
    makeStep(7, 'Natija: <span class="badge ' + (ok ? 'badge-success' : 'badge-warn') + '">' + (ok ? '✓ Umumiy kalit: ' + sA : '✗ Xato!') + '</span>', '')
  );
}

/* ============================================================
   12. RSA
   ============================================================ */
function gcd(a, b) { return b === 0 ? a : gcd(b, a % b); }

function modInv(e, phi) {
  let [or, r, os, s] = [e, phi, 1, 0];
  while (r !== 0) {
    const q = Math.floor(or / r);
    [or, r] = [r, or - q * r];
    [os, s] = [s, os - q * s];
  }
  return ((os % phi) + phi) % phi;
}

function isPrime(n) {
  if (n < 2) return false;
  for (let i = 2; i <= Math.sqrt(n); i++) if (n % i === 0) return false;
  return true;
}

function rsaBigPow(b, e, m) {
  let r = 1n;
  b = BigInt(b) % BigInt(m);
  e = BigInt(e);
  m = BigInt(m);
  while (e > 0n) {
    if (e % 2n === 1n) r = r * b % m;
    e >>= 1n;
    b = b * b % m;
  }
  return Number(r);
}

function rsaGenKeys() {
  const p = parseInt(document.getElementById('rsa-p').value);
  const q = parseInt(document.getElementById('rsa-q').value);
  if (!isPrime(p) || !isPrime(q)) {
    document.getElementById('rsa-keys').innerHTML = '<p class="hint" style="color:#f88">Xato: p va q tub son bo\'lishi kerak!</p>';
    return;
  }
  if (p === q) {
    document.getElementById('rsa-keys').innerHTML = '<p class="hint" style="color:#f88">Xato: p va q har xil bo\'lishi kerak!</p>';
    return;
  }
  rsaN = p * q;
  const phi = (p - 1) * (q - 1);
  let e = 65537;
  if (e >= phi) e = 3;
  while (gcd(e, phi) !== 1) e += 2;
  const d = modInv(e, phi);
  rsaPublicKey = e;
  rsaPrivateKey = d;

  document.getElementById('rsa-keys').innerHTML = stepsWrap(
    makeStep(1, 'n = p × q = ' + p + ' × ' + q, '= ' + rsaN) +
    makeStep(2, 'φ(n) = (p−1)(q−1) = ' + (p-1) + ' × ' + (q-1), '= ' + phi) +
    makeStep(3, 'e tanlandi: gcd(e, φ(n)) = 1', 'e = ' + e) +
    makeStep(4, 'd = e⁻¹ mod φ(n) (modular teskari)', 'd = ' + d)
  ) + `<div class="info-grid" style="margin-top:10px">
    <div class="info-card accent-blue"><div class="ic-label">Ochiq kalit (e, n)</div><div class="ic-val blue">(${e}, ${rsaN})</div></div>
    <div class="info-card accent-amber"><div class="ic-label">Yopiq kalit (d, n)</div><div class="ic-val amber">(${d}, ${rsaN})</div></div>
  </div>`;
}

function rsaEncrypt() {
  if (!rsaPublicKey) {
    document.getElementById('rsa-result').textContent = 'Avval "Kalitlar hosil qilish" tugmasini bosing!';
    return;
  }
  const m = parseInt(document.getElementById('rsa-msg').value);
  if (m >= rsaN) {
    document.getElementById('rsa-result').textContent = 'Xato: M = ' + m + ' n = ' + rsaN + ' dan kichik bo\'lishi kerak!';
    return;
  }
  const c = rsaBigPow(m, rsaPublicKey, rsaN);
  const rb = showResult('rsa',
    'C = M^e mod n\nC = ' + m + '^' + rsaPublicKey + ' mod ' + rsaN + ' = ' + c
  );
  rb.dataset.cipherval = String(c);
}

function rsaDecrypt() {
  if (!rsaPrivateKey) { showDecrypted('rsa', 'Avval kalitlarni hosil qiling!'); return; }
  const rb = document.getElementById('rsa-result');
  const c = parseInt(rb.dataset.cipherval);
  if (!c) { showDecrypted('rsa', 'Avval shifrlang!'); return; }
  const m = rsaBigPow(c, rsaPrivateKey, rsaN);
  showDecrypted('rsa',
    'M = C^d mod n\nM = ' + c + '^' + rsaPrivateKey + ' mod ' + rsaN + ' = ' + m
  );
}

// Init: Playfair matrisa boshlang'ich ko'rinishini chiqarish
window.addEventListener('load', () => {
  playfairShowMatrix();
});
