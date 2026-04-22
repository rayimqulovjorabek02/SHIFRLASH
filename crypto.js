/* ============================================================
   CRYPTO LAB — crypto.js
   Barcha shifrlash algoritmlari shu faylda
   ============================================================ */

// Foydalanuvchilar bazasi (xotirada saqlanadi)
const users = {};

// RSA holat o'zgaruvchilari
let rsaPublicKey = null;
let rsaPrivateKey = null;
let rsaN = null;

// ============================================================
// YORDAMCHI FUNKSIYALAR
// ============================================================

/** Panel ko'rsatish */
function showPanel(id, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

/** HTML yaratish yordamchi */
function makeStep(num, title, val) {
  return `
    <div class="step">
      <div class="step-num">${num}</div>
      <div class="step-text">${title}
        ${val ? `<div class="step-val">${val}</div>` : ''}
      </div>
    </div>`;
}

function stepsWrap(html) {
  return `<div class="steps-wrap">${html}</div>`;
}

// ============================================================
// 1. KLASSIK SHIFRLASH
// ============================================================

function classicAlgoChange() {
  const algo = document.getElementById('classic-algo').value;
  document.getElementById('caesar-key-wrap').style.display = algo === 'caesar' ? '' : 'none';
  document.getElementById('vig-key-wrap').style.display  = algo === 'vigenere' ? '' : 'none';
}

/** Sezar shifri */
function caesarShift(text, shift) {
  return text.split('').map(c => {
    if (c >= 'A' && c <= 'Z') return String.fromCharCode((c.charCodeAt(0) - 65 + shift + 26) % 26 + 65);
    if (c >= 'a' && c <= 'z') return String.fromCharCode((c.charCodeAt(0) - 97 + shift + 26) % 26 + 97);
    return c;
  }).join('');
}

/** Vigenère shifri */
function vigenereShift(text, key, enc) {
  key = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!key) key = 'KEY';
  let ki = 0;
  return text.split('').map(c => {
    const upper = c >= 'A' && c <= 'Z';
    const lower = c >= 'a' && c <= 'z';
    if (!upper && !lower) return c;
    const base  = upper ? 65 : 97;
    const ksh   = key[ki % key.length].charCodeAt(0) - 65;
    const shift = enc ? ksh : 26 - ksh;
    ki++;
    return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base);
  }).join('');
}

/** Atbash shifri */
function atbash(text) {
  return text.split('').map(c => {
    if (c >= 'A' && c <= 'Z') return String.fromCharCode(90 - (c.charCodeAt(0) - 65));
    if (c >= 'a' && c <= 'z') return String.fromCharCode(122 - (c.charCodeAt(0) - 97));
    return c;
  }).join('');
}

function classicEncrypt() {
  const algo = document.getElementById('classic-algo').value;
  const text = document.getElementById('classic-input').value;
  let result = '', stepsHtml = '';

  if (algo === 'caesar') {
    const k = parseInt(document.getElementById('caesar-key').value);
    result = caesarShift(text, k);
    stepsHtml =
      makeStep(1, 'Har bir harf ' + k + ' pozitsiyaga o\'ngga siljitiladi',
               'A(0) + ' + k + ' = ' + String.fromCharCode(65 + (k % 26)) + '(' + k + ')') +
      makeStep(2, 'Alifbo chegarasida aylanadi (mod 26)', 'Z + 3 = C') +
      makeStep(3, 'Raqam va boshqa belgilar o\'zgarmaydi', '');
  } else if (algo === 'vigenere') {
    const k = document.getElementById('vig-key').value || 'KEY';
    result = vigenereShift(text, k, true);
    stepsHtml =
      makeStep(1, 'Kalit: <b>' + k.toUpperCase() + '</b> — har harfga navbatma-navbat qo\'llanadi', '') +
      makeStep(2, 'Har harf kalit harfi qiymati bilan siljitiladi',
               'A + K(10) = K, B + E(4) = F, ...') +
      makeStep(3, 'Kalit tugasa, boshidan takrorlanadi', '');
  } else {
    result = atbash(text);
    stepsHtml =
      makeStep(1, 'Har harf alifboning teskarisiga almashadi', 'A↔Z, B↔Y, C↔X ...') +
      makeStep(2, 'Atbash o\'z-o\'ziga teskari — bir xil funksiya', '');
  }

  document.getElementById('classic-result').textContent = result;
  document.getElementById('classic-steps').innerHTML = stepsWrap(stepsHtml);
}

function classicDecrypt() {
  const algo = document.getElementById('classic-algo').value;
  const text = document.getElementById('classic-input').value;
  let result = '';

  if (algo === 'caesar') {
    const k = parseInt(document.getElementById('caesar-key').value);
    result = caesarShift(text, -k);
  } else if (algo === 'vigenere') {
    const k = document.getElementById('vig-key').value || 'KEY';
    result = vigenereShift(text, k, false);
  } else {
    result = atbash(text); // atbash o'z-o'ziga teskari
  }

  document.getElementById('classic-result').textContent = result;
  document.getElementById('classic-steps').innerHTML = '';
}

function classicClear() {
  document.getElementById('classic-input').value = '';
  document.getElementById('classic-result').textContent = '—';
  document.getElementById('classic-steps').innerHTML = '';
}

// ============================================================
// 2. SODDA SHIFRLASH
// ============================================================

function simpleAlgoChange() {
  const algo = document.getElementById('simple-algo').value;
  document.getElementById('xor-wrap').style.display = algo === 'xor' ? '' : 'none';
}

function simpleEncrypt() {
  const algo = document.getElementById('simple-algo').value;
  const text = document.getElementById('simple-input').value;
  let result = '';

  try {
    if (algo === 'base64') {
      result = btoa(unescape(encodeURIComponent(text)));
    } else if (algo === 'rot13') {
      result = text.replace(/[a-zA-Z]/g, c => {
        const b = c <= 'Z' ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
      });
    } else if (algo === 'xor') {
      const k = parseInt(document.getElementById('xor-key').value);
      const xored = Array.from(text).map(c =>
        String.fromCharCode(c.charCodeAt(0) ^ k)
      ).join('');
      result = btoa(xored);
    } else if (algo === 'hex') {
      result = Array.from(text)
        .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ');
    } else if (algo === 'binary') {
      result = Array.from(text)
        .map(c => c.charCodeAt(0).toString(2).padStart(8, '0'))
        .join(' ');
    }
  } catch (e) {
    result = 'Xato: ' + e.message;
  }

  document.getElementById('simple-result').textContent = result;
}

function simpleDecrypt() {
  const algo = document.getElementById('simple-algo').value;
  const text = document.getElementById('simple-input').value;
  let result = '';

  try {
    if (algo === 'base64') {
      result = decodeURIComponent(escape(atob(text)));
    } else if (algo === 'rot13') {
      result = text.replace(/[a-zA-Z]/g, c => {
        const b = c <= 'Z' ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
      });
    } else if (algo === 'xor') {
      const k = parseInt(document.getElementById('xor-key').value);
      const decoded = atob(text);
      result = Array.from(decoded)
        .map(c => String.fromCharCode(c.charCodeAt(0) ^ k))
        .join('');
    } else if (algo === 'hex') {
      result = text.split(' ')
        .map(h => String.fromCharCode(parseInt(h, 16)))
        .join('');
    } else if (algo === 'binary') {
      result = text.split(' ')
        .map(b => String.fromCharCode(parseInt(b, 2)))
        .join('');
    }
  } catch (e) {
    result = 'Xato: ' + e.message;
  }

  document.getElementById('simple-result').textContent = result;
}

// ============================================================
// 3. STEGANOGRAFIYA
// ============================================================

// Zero-width belgilar: 0 = U+200B, 1 = U+200C
const ZW0 = '\u200B'; // 0 bit
const ZW1 = '\u200C'; // 1 bit
const ZWE = '\uFEFF'; // tugash belgisi

function stegHide() {
  const secret = document.getElementById('steg-secret').value;
  const cover  = document.getElementById('steg-cover').value;

  // Maxfiy matnni bitlarga aylantir
  const bits = Array.from(secret).flatMap(c => {
    const code = c.charCodeAt(0);
    return Array.from({ length: 8 }, (_, i) => (code >> (7 - i)) & 1);
  });

  // Bitlarni zero-width belgilarga aylantir
  const hidden = bits.map(b => b ? ZW1 : ZW0).join('') + ZWE;

  document.getElementById('steg-result').textContent =
    cover + hidden +
    '\n\n[' + bits.length + ' ta ko\'rinmas bit yashirildi — matn uzunligi: ' +
    (cover + hidden).length + ' belgi]';
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

  let result = '';
  for (let i = 0; i < bits.length - 7; i += 8) {
    let code = 0;
    for (let j = 0; j < 8; j++) code = (code << 1) | bits[i + j];
    if (code > 0) result += String.fromCharCode(code);
  }

  document.getElementById('steg-result').textContent =
    result ? 'Topildi: ' + result : 'Yashirilgan matn topilmadi.';
}

// ============================================================
// 4. DIFFIE-HELLMAN
// ============================================================

/** BigInt modular exponentiation */
function modPow(base, exp, mod) {
  let result = 1n;
  base = BigInt(base) % BigInt(mod);
  exp  = BigInt(exp);
  mod  = BigInt(mod);
  while (exp > 0n) {
    if (exp % 2n === 1n) result = result * base % mod;
    exp  = exp >> 1n;
    base = base * base % mod;
  }
  return Number(result);
}

function dhGenerate() {
  const p = parseInt(document.getElementById('dh-p').value);
  const g = parseInt(document.getElementById('dh-g').value);

  if (p < 5 || g < 2) {
    document.getElementById('dh-steps').innerHTML =
      '<p class="hint" style="color:#ff6644">Xato: p >= 5 va g >= 2 bo\'lishi kerak</p>';
    return;
  }

  // Tasodifiy maxfiy kalitlar
  const a = Math.floor(Math.random() * (p - 3)) + 2;
  const b = Math.floor(Math.random() * (p - 3)) + 2;

  // Ochiq kalitlar
  const A = modPow(g, a, p);
  const B = modPow(g, b, p);

  // Umumiy sir
  const sA = modPow(B, a, p);
  const sB = modPow(A, b, p);
  const ok = sA === sB;

  document.getElementById('dh-steps').innerHTML = stepsWrap(
    makeStep(1, 'Umumiy ochiq parametrlar', `p = ${p} (tub son),  g = ${g} (generator)`) +
    makeStep(2, 'Alice o\'zining maxfiy kalitini tanlaydi', `a = ${a}  (faqat Alice biladi)`) +
    makeStep(3, 'Bob o\'zining maxfiy kalitini tanlaydi',  `b = ${b}  (faqat Bob biladi)`) +
    makeStep(4, 'Alice ochiq kalitini hisoblaydi va yuboradi',
             `A = g^a mod p = ${g}^${a} mod ${p} = ${A}`) +
    makeStep(5, 'Bob ochiq kalitini hisoblaydi va yuboradi',
             `B = g^b mod p = ${g}^${b} mod ${p} = ${B}`) +
    makeStep(6,
             `Umumiy sir kalit <span class="badge ${ok ? 'badge-success' : 'badge-warn'}">${ok ? 'mos keldi ✓' : 'xato!'}</span>`,
             `Alice: B^a mod p = ${sA}\nBob:   A^b mod p = ${sB}`)
  );
}

// ============================================================
// 5. RSA
// ============================================================

function gcd(a, b) { return b === 0 ? a : gcd(b, a % b); }

function modInverse(e, phi) {
  let [old_r, r]   = [e, phi];
  let [old_s, s]   = [1, 0];
  while (r !== 0) {
    const q = Math.floor(old_r / r);
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % phi) + phi) % phi;
}

function isPrime(n) {
  if (n < 2) return false;
  for (let i = 2; i <= Math.sqrt(n); i++) if (n % i === 0) return false;
  return true;
}

function rsaBigPow(base, exp, mod) {
  let result = 1n;
  base = BigInt(base) % BigInt(mod);
  exp  = BigInt(exp);
  mod  = BigInt(mod);
  while (exp > 0n) {
    if (exp % 2n === 1n) result = result * base % mod;
    exp  >>= 1n;
    base = base * base % mod;
  }
  return Number(result);
}

function rsaGenKeys() {
  const p = parseInt(document.getElementById('rsa-p').value);
  const q = parseInt(document.getElementById('rsa-q').value);

  if (!isPrime(p) || !isPrime(q)) {
    document.getElementById('rsa-keys').innerHTML =
      '<p class="hint" style="color:#ff6644">Xato: p va q tub son bo\'lishi kerak!</p>';
    return;
  }
  if (p === q) {
    document.getElementById('rsa-keys').innerHTML =
      '<p class="hint" style="color:#ff6644">Xato: p va q har xil bo\'lishi kerak!</p>';
    return;
  }

  rsaN = p * q;
  const phi = (p - 1) * (q - 1);

  // e tanlash
  let e = 65537;
  if (e >= phi) e = 3;
  while (gcd(e, phi) !== 1) e += 2;

  const d = modInverse(e, phi);
  rsaPublicKey  = e;
  rsaPrivateKey = d;

  document.getElementById('rsa-keys').innerHTML = `
    <div class="info-grid">
      <div class="info-card">
        <div class="ic-label">n = p × q</div>
        <div class="ic-val">${rsaN}</div>
      </div>
      <div class="info-card">
        <div class="ic-label">φ(n) = (p-1)(q-1)</div>
        <div class="ic-val">${phi}</div>
      </div>
      <div class="info-card accent-blue">
        <div class="ic-label">Ochiq kalit (e, n)</div>
        <div class="ic-val blue">(${e}, ${rsaN})</div>
      </div>
      <div class="info-card accent-amber">
        <div class="ic-label">Yopiq kalit (d, n)</div>
        <div class="ic-val amber">(${d}, ${rsaN})</div>
      </div>
    </div>`;
}

function rsaEncrypt() {
  if (!rsaPublicKey) {
    document.getElementById('rsa-result').textContent = 'Avval kalitlarni hosil qiling!';
    return;
  }
  const m = parseInt(document.getElementById('rsa-msg').value);
  if (m >= rsaN) {
    document.getElementById('rsa-result').textContent =
      `Xato: xabar n=${rsaN} dan kichik bo'lishi kerak`;
    return;
  }
  const c = rsaBigPow(m, rsaPublicKey, rsaN);
  document.getElementById('rsa-result').textContent =
    `Shifrlangan:\nC = M^e mod n\nC = ${m}^${rsaPublicKey} mod ${rsaN} = ${c}`;
}

function rsaDecrypt() {
  if (!rsaPrivateKey) {
    document.getElementById('rsa-result').textContent = 'Avval kalitlarni hosil qiling!';
    return;
  }
  const text  = document.getElementById('rsa-result').textContent;
  const match = text.match(/= (\d+)$/);
  if (!match) {
    document.getElementById('rsa-result').textContent = 'Avval shifrlang!';
    return;
  }
  const c = parseInt(match[1]);
  const m = rsaBigPow(c, rsaPrivateKey, rsaN);
  document.getElementById('rsa-result').textContent =
    `Deshifrlangan:\nM = C^d mod n\nM = ${c}^${rsaPrivateKey} mod ${rsaN} = ${m}`;
}

// ============================================================
// 6. PKI
// ============================================================

function pkiSimulate() {
  const steps = [
    ['CA (Certificate Authority)',   'RSA kalit juftligi yaratildi',           'CA ochiq kaliti: (e=65537, n=3233)'],
    ['Foydalanuvchi (Alice)',         'Sertifikat so\'rovi (CSR) tayyorlandi',   'CSR: Alice + ochiq kalit + elektron imzo'],
    ['CA tekshirish',                 'Alice shaxsi tasdiqlandi',                'DN: CN=Alice, O=CryptoLab, C=UZ'],
    ['Sertifikat chiqarish',          'CA sertifikatni imzoladi',               'X.509 v3, amal muddati: 365 kun'],
    ['CRL / OCSP',                    'Sertifikat e\'lon qilindi',              'Bekor qilingan sertifikatlar ro\'yxati yangilandi'],
    ['Bob tekshiradi',                'Alice sertifikatini CA orqali tasdiqladi','Ishonch zanjiri: Alice → Intermediate CA → Root CA'],
  ];

  const html = steps.map((s, i) =>
    makeStep(i + 1, `<b>${s[0]}</b> — ${s[1]}`, s[2])
  ).join('');

  document.getElementById('pki-steps').innerHTML = stepsWrap(html);
}

// ============================================================
// 7. TRUECRYPT USLUBI
// ============================================================

/** Oddiy kalit derivatsiyasi (PBKDF simulyatsiyasi) */
function deriveKey(pass, salt) {
  const combined = pass + salt;
  let key = 0x12345678;
  for (let i = 0; i < combined.length; i++) {
    key = Math.imul(key ^ combined.charCodeAt(i), 0x9e3779b9);
    key = (key << 13) | (key >>> 19);
  }
  // Bir necha davr (PBKDF iteratsiyasi simulyatsiyasi)
  for (let round = 0; round < 1000; round++) {
    key = Math.imul(key ^ round, 0x85ebca6b);
  }
  return Math.abs(key) % 256;
}

function tcEncrypt() {
  const pass = document.getElementById('tc-pass').value;
  const salt = document.getElementById('tc-salt').value;
  const text = document.getElementById('tc-input').value;

  const key = deriveKey(pass, salt);

  const encrypted = Array.from(text)
    .map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ ((key + i) % 256)))
    .join('');

  const b64 = btoa(encrypted);

  document.getElementById('tc-result').textContent =
    `Kalit (derived): 0x${key.toString(16).padStart(2, '0').toUpperCase()}\n` +
    `Salt: ${salt}\n` +
    `Shifrlangan (Base64):\n${b64}`;
}

function tcDecrypt() {
  const pass   = document.getElementById('tc-pass').value;
  const salt   = document.getElementById('tc-salt').value;
  const result = document.getElementById('tc-result').textContent;

  const b64match = result.match(/Base64\):\n(.+)/s);
  if (!b64match) {
    document.getElementById('tc-result').textContent = 'Avval shifrlang!';
    return;
  }

  const key = deriveKey(pass, salt);
  try {
    const encrypted  = atob(b64match[1].trim());
    const decrypted  = Array.from(encrypted)
      .map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ ((key + i) % 256)))
      .join('');
    document.getElementById('tc-result').textContent = 'Deshifrlangan matni:\n' + decrypted;
  } catch (e) {
    document.getElementById('tc-result').textContent = 'Xato: ' + e.message;
  }
}

// ============================================================
// 8. AUTENTIFIKATSIYA (SHA-256 + Salt)
// ============================================================

function authTab(t) {
  document.getElementById('auth-reg').style.display = t === 'reg' ? '' : 'none';
  document.getElementById('auth-log').style.display = t === 'log' ? '' : 'none';
  document.getElementById('auth-reg-btn').classList.toggle('primary', t === 'reg');
  document.getElementById('auth-log-btn').classList.toggle('primary', t === 'log');
}

async function sha256(str) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function authRegister() {
  const user = document.getElementById('auth-user').value.trim();
  const pass = document.getElementById('auth-pass').value;

  if (!user || !pass) {
    document.getElementById('auth-reg-result').innerHTML =
      '<p class="hint" style="color:#ff6644">Foydalanuvchi nomi va parol kiritilishi shart!</p>';
    return;
  }

  const salt = Math.random().toString(36).substring(2, 12);
  const hash = await sha256(salt + pass);
  users[user] = { salt, hash };

  document.getElementById('auth-reg-result').innerHTML = stepsWrap(
    makeStep(1, `Foydalanuvchi: <b>${user}</b>`, '') +
    makeStep(2, 'Tasodifiy tuz (salt) yaratildi', salt) +
    makeStep(3, 'SHA-256(salt + parol) hisoblanadi',
             hash.substring(0, 32) + '...') +
    makeStep(4,
             `<span class="badge badge-success">Muvaffaqiyatli saqlandi</span> ` +
             `Parol hech qachon ochiq holda saqlanmaydi`, '')
  );
}

async function authLogin() {
  const user = document.getElementById('auth-user2').value.trim();
  const pass = document.getElementById('auth-pass2').value;

  if (!users[user]) {
    document.getElementById('auth-log-result').innerHTML =
      stepsWrap(makeStep('!', 'Foydalanuvchi topilmadi', 'Avval ro\'yxatdan o\'ting'));
    return;
  }

  const { salt, hash } = users[user];
  const attempt = await sha256(salt + pass);
  const ok = attempt === hash;

  document.getElementById('auth-log-result').innerHTML = stepsWrap(
    makeStep(1, 'Saqlangan salt olinadi', salt) +
    makeStep(2, 'SHA-256(salt + kiritilgan parol) hisoblanadi',
             attempt.substring(0, 32) + '...') +
    makeStep(3, 'Xeshlar taqqoslanadi',
             `Saqlangan:  ${hash.substring(0, 20)}...\nHisoblangan: ${attempt.substring(0, 20)}...`) +
    makeStep(4,
             `<span class="badge ${ok ? 'badge-success' : 'badge-warn'}">${ok ? '✓ Kirish muvaffaqiyatli!' : '✗ Parol noto\'g\'ri!'}</span>`, '')
  );
}