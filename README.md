# 🔐 Crypto Lab — Shifrlash Laboratoriyasi

Axborot xavfsizligi fanidan amaliy mashg'ulotlar uchun interaktiv veb-dastur.

## Fayllar tuzilmasi

```
crypto_lab/
├── index.html   — Asosiy HTML sahifa
├── style.css    — Dizayn va uslublar
├── crypto.js    — Barcha algoritmlar
└── README.md    — Ushbu fayl
```

## Modullar

| # | Modul | Algoritm |
|---|-------|----------|
| 1 | Klassik shifrlash | Sezar, Vigenère, Atbash |
| 2 | Sodda shifrlash | Base64, ROT13, XOR, HEX, Binary |
| 3 | Steganografiya | Unicode zero-width bits (LSB) |
| 4 | Diffie-Hellman | Kalit almashinuvi protokoli |
| 5 | RSA | Ochiq/yopiq kalit kriptografiyasi |
| 6 | PKI | X.509 sertifikat zanjiri simulyatsiyasi |
| 7 | TrueCrypt uslubi | Parol + salt + XOR shifrlash |
| 8 | Autentifikatsiya | SHA-256 + salt xeshlash |

## Ishga tushirish

Dasturni ishlatish uchun `index.html` faylini brauzerda oching.

Hech qanday server yoki qo'shimcha o'rnatish talab qilinmaydi —
barcha kod brauzerda to'g'ridan-to'g'ri ishlaydi.

## Texnologiyalar

- **HTML5** — tuzilma
- **CSS3** — dizayn
- **JavaScript (ES2020+)** — algoritmlar
- **Web Crypto API** — SHA-256 uchun (`crypto.subtle`)
- **BigInt** — katta sonlar bilan ishlash (RSA, DH)

## Eslatmalar

- RSA va Diffie-Hellman dastlabki tushuncha uchun kichik sonlar bilan ishlaydi.
- TrueCrypt moduli haqiqiy AES emas, o'quv maqsadida XOR asosida.
- SHA-256 brauzerning o'z `crypto.subtle` API'si orqali hisoblanadi.