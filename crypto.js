/* CRYPTO LAB - crypto.js - Barcha 15 ta shifrlash moduli */

const users = {};
let rsaPublicKey = null, rsaPrivateKey = null, rsaN = null;

/* ---- HELPERS ---- */
function showPanel(id, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}
function makeStep(n, t, v) {
  return `<div class="step"><div class="step-num">${n}</div><div class="step-text">${t}${v ? `<div class="step-val">${v}</div>` : ''}</div></div>`;
}
function stepsWrap(h) { return `<div class="steps-wrap">${h}</div>`; }

function showResult(prefix, val, extraClass) {
  const rb = document.getElementById(prefix + '-result');
  rb.textContent = val;
  rb.classList.add('has-action');
  if (extraClass) rb.classList.add(extraClass);
  document.getElementById(prefix + '-decrypt-action').style.display = 'flex';
  document.getElementById(prefix + '-decrypted-box').style.display = 'none';
  return rb;
}
function showDecrypted(prefix, val) {
  document.getElementById(prefix + '-decrypted').textContent = val;
  document.getElementById(prefix + '-decrypted-box').style.display = 'block';
}
function clearPanel(prefix, extras) {
  const rb = document.getElementById(prefix + '-result');
  rb.textContent = '-'; rb.classList.remove('has-action');
  document.getElementById(prefix + '-decrypt-action').style.display = 'none';
  document.getElementById(prefix + '-decrypted-box').style.display = 'none';
  if (extras) extras.forEach(id => { const el = document.getElementById(id); if(el) el.innerHTML = ''; });
}

/* ========== 1. KLASSIK ========== */
function classicAlgoChange() {
  const v = document.getElementById('classic-algo').value;
  document.getElementById('caesar-key-wrap').style.display = v === 'caesar' ? '' : 'none';
  document.getElementById('vig-key-wrap').style.display = v === 'vigenere' ? '' : 'none';
}
function caesarShift(t, s) {
  return t.split('').map(c => {
    if (c >= 'A' && c <= 'Z') return String.fromCharCode((c.charCodeAt(0)-65+s+260) % 26 + 65);
    if (c >= 'a' && c <= 'z') return String.fromCharCode((c.charCodeAt(0)-97+s+260) % 26 + 97);
    return c;
  }).join('');
}
function vigenereShift(text, key, enc) {
  key = key.toUpperCase().replace(/[^A-Z]/g, '') || 'KEY';
  let ki = 0;
  return text.split('').map(c => {
    const up = c >= 'A' && c <= 'Z', lo = c >= 'a' && c <= 'z';
    if (!up && !lo) return c;
    const base = up ? 65 : 97, ks = key[ki++ % key.length].charCodeAt(0) - 65;
    return String.fromCharCode((c.charCodeAt(0) - base + (enc ? ks : 26-ks)) % 26 + base);
  }).join('');
}
function atbash(t) {
  return t.split('').map(c => {
    if (c >= 'A' && c <= 'Z') return String.fromCharCode(90 - (c.charCodeAt(0)-65));
    if (c >= 'a' && c <= 'z') return String.fromCharCode(122 - (c.charCodeAt(0)-97));
    return c;
  }).join('');
}
function classicEncrypt() {
  const algo = document.getElementById('classic-algo').value;
  const text = document.getElementById('classic-input').value; if (!text.trim()) return;
  let result = '', steps = '';
  if (algo === 'caesar') {
    const k = parseInt(document.getElementById('caesar-key').value);
    result = caesarShift(text, k);
    steps = makeStep(1,'Har harf '+k+' pozitsiya siljitiladi','A+'+k+'='+String.fromCharCode(65+(k%26))) +
            makeStep(2,'Alifbo chegarasida aylanadi (mod 26)','Z+3=C') +
            makeStep(3,'Raqam va boshqa belgilar ozgarmaydi','');
  } else if (algo === 'vigenere') {
    const k = document.getElementById('vig-key').value || 'KEY';
    result = vigenereShift(text, k, true);
    steps = makeStep(1,'Kalit: '+k.toUpperCase()+' takrorlanib harflarga qollaniladi','') +
            makeStep(2,'Har harf kalit harfi bilan siljitiladi','A+K(10)=K, B+E(4)=F');
  } else {
    result = atbash(text);
    steps = makeStep(1,'Har harf teskarisiga almashadi','A-Z, B-Y, C-X ...');
  }
  showResult('classic', result);
  document.getElementById('classic-steps').innerHTML = stepsWrap(steps);
}
function classicDecryptFromResult() {
  const algo = document.getElementById('classic-algo').value;
  const enc = document.getElementById('classic-result').textContent; if (!enc || enc==='-') return;
  let r = '';
  if (algo === 'caesar') r = caesarShift(enc, -parseInt(document.getElementById('caesar-key').value));
  else if (algo === 'vigenere') r = vigenereShift(enc, document.getElementById('vig-key').value||'KEY', false);
  else r = atbash(enc);
  showDecrypted('classic', r);
}
function classicClear() { document.getElementById('classic-input').value=''; clearPanel('classic',['classic-steps']); document.getElementById('classic-result').textContent='-'; }

/* ========== 2. SODDA ========== */
function simpleAlgoChange() {
  document.getElementById('xor-wrap').style.display = document.getElementById('simple-algo').value === 'xor' ? '' : 'none';
}
function simpleEncrypt() {
  const algo = document.getElementById('simple-algo').value;
  const text = document.getElementById('simple-input').value; if (!text.trim()) return;
  let r = '';
  try {
    if (algo==='base64') r = btoa(unescape(encodeURIComponent(text)));
    else if (algo==='rot13') r = text.replace(/[a-zA-Z]/g,c=>{const b=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-b+13)%26+b);});
    else if (algo==='xor') { const k=parseInt(document.getElementById('xor-key').value); r = btoa(Array.from(text).map(c=>String.fromCharCode(c.charCodeAt(0)^k)).join('')); }
    else if (algo==='hex') r = Array.from(text).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
    else if (algo==='binary') r = Array.from(text).map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' ');
  } catch(e) { r = 'Xato: '+e.message; }
  showResult('simple', r);
}
function simpleDecryptFromResult() {
  const algo = document.getElementById('simple-algo').value;
  const enc = document.getElementById('simple-result').textContent; if (!enc||enc==='-') return;
  let r = '';
  try {
    if (algo==='base64') r = decodeURIComponent(escape(atob(enc)));
    else if (algo==='rot13') r = enc.replace(/[a-zA-Z]/g,c=>{const b=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-b+13)%26+b);});
    else if (algo==='xor') { const k=parseInt(document.getElementById('xor-key').value); r=Array.from(atob(enc)).map(c=>String.fromCharCode(c.charCodeAt(0)^k)).join(''); }
    else if (algo==='hex') r = enc.split(' ').map(h=>String.fromCharCode(parseInt(h,16))).join('');
    else if (algo==='binary') r = enc.split(' ').map(b=>String.fromCharCode(parseInt(b,2))).join('');
  } catch(e) { r='Xato: '+e.message; }
  showDecrypted('simple', r);
}
function simpleClear() { document.getElementById('simple-input').value=''; clearPanel('simple',[]); document.getElementById('simple-result').textContent='-'; }

/* ========== 3. STEGANOGRAFIYA ========== */
const ZW0='\u200B', ZW1='\u200C', ZWE='\uFEFF';
function stegHide() {
  const sec=document.getElementById('steg-secret').value, cov=document.getElementById('steg-cover').value;
  const bits=Array.from(sec).flatMap(c=>Array.from({length:8},(_,i)=>(c.charCodeAt(0)>>(7-i))&1));
  document.getElementById('steg-result').textContent = cov + bits.map(b=>b?ZW1:ZW0).join('') + ZWE + '\n\n['+bits.length+' ta bit yashirildi]';
}
function stegReveal() {
  const text=document.getElementById('steg-result').textContent;
  const bits=[]; for(const c of text){if(c===ZW0)bits.push(0);else if(c===ZW1)bits.push(1);else if(c===ZWE)break;}
  let r=''; for(let i=0;i<bits.length-7;i+=8){let code=0;for(let j=0;j<8;j++)code=(code<<1)|bits[i+j];if(code>0)r+=String.fromCharCode(code);}
  document.getElementById('steg-result').textContent = r ? 'Topildi: '+r : 'Yashirilgan matn topilmadi';
}

/* ========== 4. DIFFIE-HELLMAN ========== */
function modPow(base,exp,mod){let r=1n;base=BigInt(base)%BigInt(mod);exp=BigInt(exp);mod=BigInt(mod);while(exp>0n){if(exp%2n===1n)r=r*base%mod;exp>>=1n;base=base*base%mod;}return Number(r);}
function dhGenerate() {
  const p=parseInt(document.getElementById('dh-p').value), g=parseInt(document.getElementById('dh-g').value);
  const a=Math.floor(Math.random()*(p-3))+2, b=Math.floor(Math.random()*(p-3))+2;
  const A=modPow(g,a,p), B=modPow(g,b,p), sA=modPow(B,a,p), sB=modPow(A,b,p);
  document.getElementById('dh-steps').innerHTML = stepsWrap(
    makeStep(1,'Umumiy parametrlar','p='+p+', g='+g) +
    makeStep(2,'Alice maxfiy kaliti','a='+a+' (faqat Alice biladi)') +
    makeStep(3,'Bob maxfiy kaliti','b='+b+' (faqat Bob biladi)') +
    makeStep(4,'Alice ochiq kaliti: A=g^a mod p','='+g+'^'+a+' mod '+p+' = '+A) +
    makeStep(5,'Bob ochiq kaliti: B=g^b mod p','='+g+'^'+b+' mod '+p+' = '+B) +
    makeStep(6,'Umumiy sir: <span class="badge '+(sA===sB?'badge-success':'badge-warn')+'">'+(sA===sB?'Mos keldi':'Xato!')+'</span>','Alice: B^a='+sA+' | Bob: A^b='+sB)
  );
}

/* ========== 5. RSA ========== */
function gcd(a,b){return b===0?a:gcd(b,a%b);}
function modInv(e,phi){let[or,r,os,s]=[e,phi,1,0];while(r!==0){const q=Math.floor(or/r);[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];}return((os%phi)+phi)%phi;}
function isPrime(n){if(n<2)return false;for(let i=2;i<=Math.sqrt(n);i++)if(n%i===0)return false;return true;}
function rsaBigPow(b,e,m){let r=1n;b=BigInt(b)%BigInt(m);e=BigInt(e);m=BigInt(m);while(e>0n){if(e%2n===1n)r=r*b%m;e>>=1n;b=b*b%m;}return Number(r);}
function rsaGenKeys() {
  const p=parseInt(document.getElementById('rsa-p').value), q=parseInt(document.getElementById('rsa-q').value);
  if(!isPrime(p)||!isPrime(q)){document.getElementById('rsa-keys').innerHTML='<p class="hint" style="color:#f66">p va q tub son bolishi kerak!</p>';return;}
  rsaN=p*q; const phi=(p-1)*(q-1); let e=65537; if(e>=phi)e=3; while(gcd(e,phi)!==1)e+=2;
  const d=modInv(e,phi); rsaPublicKey=e; rsaPrivateKey=d;
  document.getElementById('rsa-keys').innerHTML=`<div class="info-grid">
    <div class="info-card"><div class="ic-label">n = p x q</div><div class="ic-val">${rsaN}</div></div>
    <div class="info-card"><div class="ic-label">fi(n) = (p-1)(q-1)</div><div class="ic-val">${phi}</div></div>
    <div class="info-card accent-blue"><div class="ic-label">Ochiq kalit (e,n)</div><div class="ic-val blue">(${e}, ${rsaN})</div></div>
    <div class="info-card accent-amber"><div class="ic-label">Yopiq kalit (d,n)</div><div class="ic-val amber">(${d}, ${rsaN})</div></div>
  </div>`;
}
function rsaEncrypt() {
  if(!rsaPublicKey){document.getElementById('rsa-result').textContent='Avval kalitlarni hosil qiling!';return;}
  const m=parseInt(document.getElementById('rsa-msg').value);
  if(m>=rsaN){document.getElementById('rsa-result').textContent='Xato: m < n bolishi kerak (n='+rsaN+')';return;}
  const c=rsaBigPow(m,rsaPublicKey,rsaN);
  const rb=showResult('rsa','C = '+m+'^'+rsaPublicKey+' mod '+rsaN+' = '+c);
  rb.dataset.cipherval=String(c);
}
function rsaDecrypt() {
  const rb=document.getElementById('rsa-result'); const c=parseInt(rb.dataset.cipherval);
  if(!c||!rsaPrivateKey){showDecrypted('rsa','Avval shifrlang!');return;}
  showDecrypted('rsa','M = '+c+'^'+rsaPrivateKey+' mod '+rsaN+' = '+rsaBigPow(c,rsaPrivateKey,rsaN));
}

/* ========== 6. PKI ========== */
function pkiSimulate() {
  const steps=[
    ['CA','RSA kalit juftligi yaratildi','CA ochiq kalit: (e=65537, n=3233)'],
    ['Alice','Sertifikat sorovi (CSR) tayyorlandi','CSR: Alice + ochiq kalit + imzo'],
    ['CA tekshirish','Alice shaxsi tasdiqlandi','DN: CN=Alice, O=CryptoLab, C=UZ'],
    ['Sertifikat','CA imzoladi','X.509 v3, muddati: 365 kun'],
    ['CRL/OCSP','Sertifikat elon qilindi','Bekor qilinganlar royxati yangilandi'],
    ['Bob','Alice sertifikatini tasdiqladi','Ishonch zanjiri: Alice -> IntCA -> RootCA'],
  ];
  document.getElementById('pki-steps').innerHTML=stepsWrap(steps.map((s,i)=>makeStep(i+1,'<b>'+s[0]+'</b> - '+s[1],s[2])).join(''));
}

/* ========== 7. TRUECRYPT ========== */
function deriveKey(pass,salt){const c=pass+salt;let k=0x12345678;for(let i=0;i<c.length;i++)k=Math.imul(k^c.charCodeAt(i),0x9e3779b9)|(0);for(let r=0;r<1000;r++)k=Math.imul(k^r,0x85ebca6b)|(0);return Math.abs(k)%256;}
function tcEncrypt() {
  const pass=document.getElementById('tc-pass').value, salt=document.getElementById('tc-salt').value;
  const text=document.getElementById('tc-input').value; if(!text.trim())return;
  const key=deriveKey(pass,salt);
  const b64=btoa(Array.from(text).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^((key+i)%256))).join(''));
  const rb=showResult('tc','Kalit: 0x'+key.toString(16).toUpperCase()+'\nSalt: '+salt+'\nBase64:\n'+b64);
  rb.dataset.b64=b64;
}
function tcDecrypt() {
  const rb=document.getElementById('tc-result'); if(!rb.dataset.b64){showDecrypted('tc','Avval shifrlang!');return;}
  const key=deriveKey(document.getElementById('tc-pass').value, document.getElementById('tc-salt').value);
  try { showDecrypted('tc', Array.from(atob(rb.dataset.b64)).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^((key+i)%256))).join('')); }
  catch(e){showDecrypted('tc','Xato: '+e.message);}
}
function tcClear(){document.getElementById('tc-input').value='';clearPanel('tc',[]);const rb=document.getElementById('tc-result');rb.textContent='-';rb.dataset.b64='';}

/* ========== 8. AUTH ========== */
function authTab(t){document.getElementById('auth-reg').style.display=t==='reg'?'':'none';document.getElementById('auth-log').style.display=t==='log'?'':'none';document.getElementById('auth-reg-btn').classList.toggle('primary',t==='reg');document.getElementById('auth-log-btn').classList.toggle('primary',t==='log');}
async function sha256(str){const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(str));return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');}
async function authRegister(){
  const user=document.getElementById('auth-user').value.trim(), pass=document.getElementById('auth-pass').value;
  if(!user||!pass){document.getElementById('auth-reg-result').innerHTML='<p class="hint" style="color:#f66">Tolidiring!</p>';return;}
  const salt=Math.random().toString(36).substring(2,12), hash=await sha256(salt+pass);
  users[user]={salt,hash};
  document.getElementById('auth-reg-result').innerHTML=stepsWrap(
    makeStep(1,'Foydalanuvchi: '+user,'')+makeStep(2,'Tasodifiy salt',salt)+makeStep(3,'SHA-256(salt+parol)',hash.substring(0,32)+'...')+makeStep(4,'<span class="badge badge-success">Saqlandi</span> Parol ochiq saqlanmaydi',''));
}
async function authLogin(){
  const user=document.getElementById('auth-user2').value.trim(), pass=document.getElementById('auth-pass2').value;
  if(!users[user]){document.getElementById('auth-log-result').innerHTML=stepsWrap(makeStep('!','Foydalanuvchi topilmadi','Avval royxatdan oting'));return;}
  const{salt,hash}=users[user], attempt=await sha256(salt+pass), ok=attempt===hash;
  document.getElementById('auth-log-result').innerHTML=stepsWrap(
    makeStep(1,'Salt olinadi',salt)+makeStep(2,'SHA-256(salt+parol)',attempt.substring(0,32)+'...')+makeStep(3,'Xeshlar taqqoslanadi','')+makeStep(4,'<span class="badge '+(ok?'badge-success':'badge-warn')+'">'+(ok?'Kirish muvaffaqiyatli!':'Parol notogri!')+'</span>',''));
}

/* ========== 9. KALIT YORDAMIDA O'RIN ALMASHTIRISH (Columnar Transposition) ========== */
function ksGetOrder(key) {
  const k = key.toUpperCase().replace(/[^A-Z]/g,'') || 'KEY';
  return k.split('').map((c,i)=>({c,i})).sort((a,b)=>a.c<b.c?-1:a.c>b.c?1:a.i-b.i).map(x=>x.i);
}
function ksTranspose(text, key) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g,'');
  const cols = key.length, rows = Math.ceil(clean.length/cols);
  const padded = clean.padEnd(rows*cols,'X');
  const order = ksGetOrder(key);
  // fill grid row by row
  const grid = [];
  for(let r=0;r<rows;r++) grid.push(padded.slice(r*cols,(r+1)*cols).split(''));
  // read by column order
  return order.map(c=>grid.map(row=>row[c]).join('')).join('');
}
function ksDeTranspose(cipher, key) {
  const cols = key.length, rows = Math.ceil(cipher.length/cols);
  const order = ksGetOrder(key);
  const colLens = Array(cols).fill(rows);
  const extra = cipher.length % cols; // not used since we pad
  const cols2d = [];
  let pos=0;
  for(const c of order){cols2d[c]=cipher.slice(pos,pos+rows).split('');pos+=rows;}
  let r='';
  for(let i=0;i<rows;i++) for(let j=0;j<cols;j++) r+=cols2d[j][i];
  return r;
}
function ksEncrypt(){
  const key=document.getElementById('ks-key').value||'ZEBRA';
  const text=document.getElementById('ks-input').value.toUpperCase().replace(/[^A-Z]/g,'');
  if(!text)return;
  const result=ksTranspose(text,key);
  showResult('ks',result);
  // show grid
  const cols=key.length, rows=Math.ceil(text.padEnd(rows*cols,'X').length/cols);
  const padded=text.padEnd(cols*Math.ceil(text.length/cols),'X');
  const order=ksGetOrder(key);
  const rankMap=Array(cols);order.forEach((c,i)=>rankMap[c]=i+1);
  let html='<div class="steps-wrap"><div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:12px;font-family:monospace">';
  html+='<tr>'+key.toUpperCase().split('').map((c,i)=>`<th style="padding:4px 8px;border:1px solid #333;color:#0af">${c}<br><span style="font-size:10px;color:#666">[${rankMap[i]}]</span></th>`).join('')+'</tr>';
  for(let r=0;r<Math.ceil(padded.length/cols);r++){html+='<tr>';for(let c=0;c<cols;c++)html+='<td style="padding:4px 8px;border:1px solid #222;text-align:center;color:#ccc">'+(padded[r*cols+c]||'')+'</td>';html+='</tr>';}
  html+='</table></div></div>';
  document.getElementById('ks-grid').innerHTML=html;
}
function ksDecryptFromResult(){
  const key=document.getElementById('ks-key').value||'ZEBRA';
  const enc=document.getElementById('ks-result').textContent; if(!enc||enc==='-')return;
  showDecrypted('ks',ksDeTranspose(enc,key));
}
function ksClear(){document.getElementById('ks-input').value='';clearPanel('ks',['ks-grid']);document.getElementById('ks-result').textContent='-';}

/* ========== 10. IKKI TOMONLAMA O'RIN ALMASHTIRISH ========== */
function dtEncrypt(){
  const k1=document.getElementById('dt-key1').value||'KALIT', k2=document.getElementById('dt-key2').value||'MAXFI';
  const text=document.getElementById('dt-input').value.toUpperCase().replace(/[^A-Z]/g,'');
  if(!text)return;
  const r=ksTranspose(ksTranspose(text,k1),k2);
  showResult('dt',r);
}
function dtDecryptFromResult(){
  const k1=document.getElementById('dt-key1').value||'KALIT', k2=document.getElementById('dt-key2').value||'MAXFI';
  const enc=document.getElementById('dt-result').textContent; if(!enc||enc==='-')return;
  showDecrypted('dt',ksDeTranspose(ksDeTranspose(enc,k2),k1));
}
function dtClear(){document.getElementById('dt-input').value='';clearPanel('dt',[]);document.getElementById('dt-result').textContent='-';}

/* ========== 11. VERNAM (One-Time Pad) ========== */
function vnGenKey(){
  const len=document.getElementById('vn-input').value.toUpperCase().replace(/[^A-Z]/g,'').length||10;
  document.getElementById('vn-key').value=Array.from({length:len},()=>String.fromCharCode(65+Math.floor(Math.random()*26))).join('');
}
function vnProcess(text,key){
  text=text.toUpperCase().replace(/[^A-Z]/g,'');
  key=key.toUpperCase().replace(/[^A-Z]/g,'');
  if(key.length<text.length){alert('Kalit matn uzunligidan qisqa!');return null;}
  return text.split('').map((c,i)=>String.fromCharCode((c.charCodeAt(0)-65+key.charCodeAt(i)-65)%26+65)).join('');
}
function vnDecryptProcess(cipher,key){
  cipher=cipher.toUpperCase().replace(/[^A-Z]/g,'');
  key=key.toUpperCase().replace(/[^A-Z]/g,'');
  return cipher.split('').map((c,i)=>String.fromCharCode((c.charCodeAt(0)-65-(key.charCodeAt(i)-65)+26)%26+65)).join('');
}
function vnEncrypt(){
  const text=document.getElementById('vn-input').value, key=document.getElementById('vn-key').value;
  const r=vnProcess(text,key); if(r===null)return;
  const rb=showResult('vn',r);
  rb.dataset.key=key.toUpperCase().replace(/[^A-Z]/g,'');
  // table
  const t=text.toUpperCase().replace(/[^A-Z]/g,''), k=key.toUpperCase().replace(/[^A-Z]/g,'');
  let html='<div class="steps-wrap"><div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:12px;font-family:monospace">';
  html+='<tr><th style="padding:3px 7px;border:1px solid #333;color:#888">Matn</th>'+t.split('').map(c=>`<td style="padding:3px 7px;border:1px solid #222;color:#ccc">${c}</td>`).join('')+'</tr>';
  html+='<tr><th style="padding:3px 7px;border:1px solid #333;color:#888">Kalit</th>'+t.split('').map((_,i)=>`<td style="padding:3px 7px;border:1px solid #222;color:#0af">${k[i]||'?'}</td>`).join('')+'</tr>';
  html+='<tr><th style="padding:3px 7px;border:1px solid #333;color:#888">Natija</th>'+r.split('').map(c=>`<td style="padding:3px 7px;border:1px solid #222;color:#0f9">${c}</td>`).join('')+'</tr>';
  html+='</table></div></div>';
  document.getElementById('vn-table').innerHTML=html;
}
function vnDecryptFromResult(){
  const enc=document.getElementById('vn-result').textContent; if(!enc||enc==='-')return;
  const key=document.getElementById('vn-result').dataset.key||document.getElementById('vn-key').value;
  showDecrypted('vn',vnDecryptProcess(enc,key));
}
function vnClear(){document.getElementById('vn-input').value='';clearPanel('vn',['vn-table']);document.getElementById('vn-result').textContent='-';}

/* ========== 12. GAMMALASH (LFSR) ========== */
function lfsrGamma(seed,poly,len){
  let state=seed, out=[];
  for(let i=0;i<len;i++){
    const bit=state&1;
    out.push(state&0xFF);
    state=state>>1;
    if(bit) state^=poly;
    if(state===0) state=seed; // prevent zero state
  }
  return out;
}
function gmEncrypt(){
  const key=parseInt(document.getElementById('gm-key').value)||12345;
  const poly=parseInt(document.getElementById('gm-poly').value)||0xB400;
  const text=document.getElementById('gm-input').value; if(!text.trim())return;
  const gamma=lfsrGamma(key,poly,text.length);
  const enc=Array.from(text).map((c,i)=>c.charCodeAt(0)^gamma[i]);
  const hexStr=enc.map(b=>b.toString(16).padStart(2,'0')).join(' ');
  const rb=showResult('gm',hexStr);
  rb.dataset.hex=hexStr;
}
function gmDecryptFromResult(){
  const rb=document.getElementById('gm-result'); if(!rb.dataset.hex)return;
  const key=parseInt(document.getElementById('gm-key').value)||12345;
  const poly=parseInt(document.getElementById('gm-poly').value)||0xB400;
  const bytes=rb.dataset.hex.split(' ').map(h=>parseInt(h,16));
  const gamma=lfsrGamma(key,poly,bytes.length);
  showDecrypted('gm',bytes.map((b,i)=>String.fromCharCode(b^gamma[i])).join(''));
}
function gmClear(){document.getElementById('gm-input').value='';clearPanel('gm',[]);const rb=document.getElementById('gm-result');rb.textContent='-';rb.dataset.hex='';}

/* ========== 13. UITSTON - PLAYFAIR ========== */
function wsBuildMatrix(key){
  const k=key.toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
  const seen=new Set(), matrix=[];
  for(const c of k+' ABCDEFGHIKLMNOPQRSTUVWXYZ'){if(c===' ')continue;if(!seen.has(c)){seen.add(c);matrix.push(c);}}
  return matrix; // 25 chars
}
function wsPos(m,c){c=c==='J'?'I':c;const i=m.indexOf(c);return i===-1?null:{r:Math.floor(i/5),c:i%5};}
function wsShowGrid(){
  const key=document.getElementById('ws-key').value||'WHEATSTONE';
  const m=wsBuildMatrix(key);
  let html='<div class="steps-wrap"><table style="border-collapse:collapse;font-size:14px;font-family:monospace;margin:0 auto">';
  for(let r=0;r<5;r++){html+='<tr>';for(let c=0;c<5;c++)html+=`<td style="width:32px;height:32px;border:1px solid #333;text-align:center;color:${r===0?'#0af':'#ccc'}">${m[r*5+c]}</td>`;html+='</tr>';}
  html+='</table></div>';
  document.getElementById('ws-grid-display').innerHTML=html;
}
function wsPrep(text){
  let t=text.toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
  let pairs=[];
  for(let i=0;i<t.length;i++){
    let a=t[i],b=t[i+1]||'X';
    if(a===b){b='X';} else i++;
    pairs.push([a,b]);
  }
  return pairs;
}
function wsEncPair(m,a,b,enc){
  const pa=wsPos(m,a), pb=wsPos(m,b); if(!pa||!pb)return a+b;
  const d=enc?1:-1;
  if(pa.r===pb.r) return m[pa.r*5+(pa.c+5+d)%5]+m[pb.r*5+(pb.c+5+d)%5];
  if(pa.c===pb.c) return m[((pa.r+5+d)%5)*5+pa.c]+m[((pb.r+5+d)%5)*5+pb.c];
  return m[pa.r*5+pb.c]+m[pb.r*5+pa.c];
}
function wsEncrypt(){
  const key=document.getElementById('ws-key').value||'WHEATSTONE';
  const text=document.getElementById('ws-input').value; if(!text.trim())return;
  const m=wsBuildMatrix(key);
  const pairs=wsPrep(text);
  const result=pairs.map(([a,b])=>wsEncPair(m,a,b,true)).join('');
  const rb=showResult('ws',result);
  rb.dataset.key=key;
  wsShowGrid();
}
function wsDecryptFromResult(){
  const rb=document.getElementById('ws-result');
  const enc=rb.textContent; if(!enc||enc==='-')return;
  const key=rb.dataset.key||document.getElementById('ws-key').value||'WHEATSTONE';
  const m=wsBuildMatrix(key);
  const pairs=wsPrep(enc);
  showDecrypted('ws',pairs.map(([a,b])=>wsEncPair(m,a,b,false)).join(''));
}
function wsClear(){document.getElementById('ws-input').value='';clearPanel('ws',[]);document.getElementById('ws-result').textContent='-';}

/* ========== 14. RYUGZAG (Rail Fence) ========== */
function zzEncryptText(text,rails){
  const n=text.length, fence=Array.from({length:rails},()=>[]);
  let rail=0,dir=1;
  for(let i=0;i<n;i++){fence[rail].push(text[i]);if(rail===0)dir=1;if(rail===rails-1)dir=-1;rail+=dir;}
  return fence.map(r=>r.join('')).join('');
}
function zzDecryptText(cipher,rails){
  const n=cipher.length;
  const pattern=[];
  let rail=0,dir=1;
  for(let i=0;i<n;i++){pattern.push(rail);if(rail===0)dir=1;if(rail===rails-1)dir=-1;rail+=dir;}
  const counts=Array(rails).fill(0);
  pattern.forEach(r=>counts[r]++);
  const rows=[]; let pos=0;
  for(let r=0;r<rails;r++){rows.push(cipher.slice(pos,pos+counts[r]).split(''));pos+=counts[r];}
  const idx=Array(rails).fill(0);
  return pattern.map(r=>{const c=rows[r][idx[r]++];return c;}).join('');
}
function zzEncrypt(){
  const rails=Math.max(2,parseInt(document.getElementById('zz-rails').value)||3);
  const text=document.getElementById('zz-input').value.toUpperCase().replace(/\s/g,'');
  if(!text)return;
  const result=zzEncryptText(text,rails);
  const rb=showResult('zz',result);
  rb.dataset.rails=String(rails);
  rb.dataset.len=String(text.length);
  // visual
  const n=text.length, fence=Array.from({length:rails},()=>Array(n).fill(' '));
  let r=0,d=1;
  for(let i=0;i<n;i++){fence[r][i]=text[i];if(r===0)d=1;if(r===rails-1)d=-1;r+=d;}
  let html='<div class="steps-wrap"><pre style="font-size:12px;color:#ccc;line-height:1.8;font-family:monospace">';
  html+=fence.map((row,i)=>'Relsa '+(i+1)+': '+row.join(' ')).join('\n');
  html+='</pre></div>';
  document.getElementById('zz-visual').innerHTML=html;
}
function zzDecryptFromResult(){
  const rb=document.getElementById('zz-result');
  const enc=rb.textContent; if(!enc||enc==='-')return;
  const rails=parseInt(rb.dataset.rails)||parseInt(document.getElementById('zz-rails').value)||3;
  showDecrypted('zz',zzDecryptText(enc,rails));
}
function zzClear(){document.getElementById('zz-input').value='';clearPanel('zz',['zz-visual']);document.getElementById('zz-result').textContent='-';}

/* ========== 15. REJIM SHIFRLASH (ECB / CBC) ========== */
function rjModeChange(){document.getElementById('rj-iv-wrap').style.display=document.getElementById('rj-mode').value==='cbc'?'':'none';}
function rjXorBlocks(a,b){return a.split('').map((c,i)=>String.fromCharCode(c.charCodeAt(0)^(b[i]||0).toString().charCodeAt(0))).join('');}
function rjEncryptBlock(block,key){
  // Simplified Vigenere-like block cipher (demo)
  return block.split('').map((c,i)=>String.fromCharCode(((c.charCodeAt(0)-32)^key.charCodeAt(i%key.length))+32)).join('');
}
function rjDecryptBlock(block,key){return rjEncryptBlock(block,key);} // XOR is symmetric
function rjSplitBlocks(text,size){const blocks=[];for(let i=0;i<text.length;i+=size)blocks.push(text.slice(i,i+size).padEnd(size,' '));return blocks;}
function rjEncrypt(){
  const mode=document.getElementById('rj-mode').value;
  const key=document.getElementById('rj-key').value.padEnd(8,' ').substring(0,8);
  const text=document.getElementById('rj-input').value; if(!text.trim())return;
  const iv=document.getElementById('rj-iv').value.padEnd(8,' ').substring(0,8);
  const blocks=rjSplitBlocks(text,8);
  let prev=iv, encBlocks=[], encBlocksRaw=[];
  for(let i=0;i<blocks.length;i++){
    let b=blocks[i];
    if(mode==='cbc') b=b.split('').map((c,j)=>String.fromCharCode(c.charCodeAt(0)^prev.charCodeAt(j))).join('');
    const enc=rjEncryptBlock(b,key);
    prev=enc; encBlocks.push(enc); encBlocksRaw.push(btoa(enc));
  }
  const result=encBlocksRaw.join('|');
  const rb=showResult('rj',result);
  rb.dataset.blocks=JSON.stringify(encBlocks);
  rb.dataset.mode=mode; rb.dataset.key=key; rb.dataset.iv=iv;
  // visual
  let html='<div class="steps-wrap">';
  html+=makeStep('i','Matn bloklarga bolinadi (8 belgi)','Bloklar soni: '+blocks.length);
  blocks.forEach((b,i)=>html+=makeStep(i+1,'Blok '+(i+1)+': "'+b.trim()+'"',mode==='cbc'&&i>0?'Oldingi blok bilan XOR (CBC)':mode==='cbc'?'IV bilan XOR (CBC)':'Mustaqil shifrlash (ECB)'));
  html+='</div>';
  document.getElementById('rj-blocks').innerHTML=html;
}
function rjDecryptFromResult(){
  const rb=document.getElementById('rj-result');
  if(!rb.dataset.blocks){showDecrypted('rj','Avval shifrlang!');return;}
  const encBlocks=JSON.parse(rb.dataset.blocks);
  const mode=rb.dataset.mode, key=rb.dataset.key, iv=rb.dataset.iv;
  let prev=iv, decBlocks=[];
  for(let i=0;i<encBlocks.length;i++){
    let d=rjDecryptBlock(encBlocks[i],key);
    if(mode==='cbc') d=d.split('').map((c,j)=>String.fromCharCode(c.charCodeAt(0)^prev.charCodeAt(j))).join('');
    prev=encBlocks[i]; decBlocks.push(d);
  }
  showDecrypted('rj',decBlocks.join('').trimEnd());
}
function rjClear(){document.getElementById('rj-input').value='';clearPanel('rj',['rj-blocks']);const rb=document.getElementById('rj-result');rb.textContent='-';rb.dataset.blocks='';}
