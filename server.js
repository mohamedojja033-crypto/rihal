const express = require('express');
const helmet = require('helmet'); const rateLimit = require('express-rate-limit');
const path = require('path');
const bcrypt = require('bcryptjs');
const fs = require("fs");
const USERS_FILE = path.join(__dirname, "users.json");
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
function getUsers() { return JSON.parse(fs.readFileSync(USERS_FILE, "utf8")); }
function saveUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }

const { Pool } = require("pg");
const pool = new Pool({ database: "rihal", host: "127.0.0.1", port: 5432, user: "u0_a511" });
const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(helmet());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/status', (req, res) => {
    res.json({
        success: true,
        platform: 'Rihal',
        message: 'منصة رحال تعمل بنجاح'
    });
});

// إنشاء حساب
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        if (!name || (!email && !phone) || !password) {
            return res.status(400).json({ success: false, message: "الاسم ووسيلة التواصل وكلمة المرور مطلوبة" });
        }
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
        }
        const normalizedEmail = email ? email.toLowerCase().trim() : null;
        const normalizedPhone = phone ? phone.trim() : null;
        const existing = await pool.query(
            "SELECT id FROM users WHERE ($1::text IS NOT NULL AND email = $1) OR ($2::text IS NOT NULL AND phone = $2)",
            [normalizedEmail, normalizedPhone]
        );
        if (existing.rows.length > 0) {
            return res.status(409).json({ success: false, message: "البريد أو رقم الهاتف مسجل بالفعل" });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await pool.query(
            "INSERT INTO users (name, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email, phone, account_status, created_at",
            [name.trim(), normalizedEmail, normalizedPhone, hashedPassword]
        );
        const user = result.rows[0];
        res.status(201).json({
            success: true,
            message: "تم إنشاء الحساب، يجب تأكيد رمز OTP قبل تفعيله",
            user: { id: user.id, name: user.name, email: user.email, phone: user.phone, account_status: user.account_status }
        });
    } catch (error) {
        console.error("REGISTER ERROR:", error);
        res.status(500).json({ success: false, message: "حدث خطأ في إنشاء الحساب" });
    }
});

app.listen(PORT, () => {
    console.log(`Rihal server is running on port ${PORT}`);
});

const jwt = require('jsonwebtoken');

app.post('/api/login', async (req, res) => {
    try {
        const { email, phone, password } = req.body;

        if ((!email && !phone) || !password) {
            return res.status(400).json({
                success: false,
                message: 'البريد الإلكتروني أو الهاتف وكلمة المرور مطلوبة'
            });
        }

        const normalizedEmail = email ? email.toLowerCase().trim() : null;
        const normalizedPhone = phone ? phone.trim() : null;

        const result = await pool.query(
            'SELECT id, name, email, phone, password, account_status, role FROM users WHERE ($1::text IS NOT NULL AND email = $1) OR ($2::text IS NOT NULL AND phone = $2) LIMIT 1',
            [normalizedEmail, normalizedPhone]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'بيانات الدخول غير صحيحة'
            });
        }

        const user = result.rows[0];

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'بيانات الدخول غير صحيحة'
            });
        }

        if (user.account_status !== 'active') {
            return res.status(403).json({
                success: false,
                message: 'الحساب غير مفعل بعد'
            });
        }

        const secret = process.env.JWT_SECRET;

        if (!secret) {
            return res.status(500).json({
                success: false,
                message: 'JWT_SECRET غير مضبوط في الخادم'
            });
        }

        const token = jwt.sign(
            {
                sub: String(user.id),
                role: user.role
            },
            secret,
            {
                expiresIn: '7d',
                issuer: 'rihal'
            }
        );

        res.json({
            success: true,
            message: 'تم تسجيل الدخول بنجاح',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });

    } catch (error) {
        console.error('LOGIN ERROR:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في تسجيل الدخول'
        });
    }
});

function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'يجب تسجيل الدخول أولاً'
        });
    }

    const token = authHeader.substring(7);

    try {
        const secret = process.env.JWT_SECRET;

        if (!secret) {
            return res.status(500).json({
                success: false,
                message: 'JWT_SECRET غير مضبوط في الخادم'
            });
        }

        req.user = jwt.verify(token, secret, {
            issuer: 'rihal'
        });

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'جلسة الدخول غير صالحة أو منتهية'
        });
    }
}

app.get('/api/me', authenticateJWT, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, phone, account_status, role, created_at FROM users WHERE id = $1',
            [req.user.sub]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'المستخدم غير موجود'
            });
        }

        res.json({
            success: true,
            user: result.rows[0]
        });
    } catch (error) {
        console.error('ME ERROR:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في جلب بيانات المستخدم'
        });
    }
});

const crypto = require('crypto');

app.post('/api/request-otp', async (req, res) => {
    try {
        const { email, phone } = req.body;

        if (!email && !phone) {
            return res.status(400).json({
                success: false,
                message: 'البريد الإلكتروني أو رقم الهاتف مطلوب'
            });
        }

        const normalizedEmail = email ? email.toLowerCase().trim() : null;
        const normalizedPhone = phone ? phone.trim() : null;
        const channel = normalizedEmail ? 'email' : 'phone';

        const result = await pool.query(
            'SELECT id, email, phone FROM users WHERE ($1::text IS NOT NULL AND email = $1) OR ($2::text IS NOT NULL AND phone = $2) LIMIT 1',
            [normalizedEmail, normalizedPhone]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'الحساب غير موجود'
            });
        }

        const user = result.rows[0];

        const recent = await pool.query(
            `SELECT id FROM verification_codes
             WHERE user_id = $1
             AND channel = $2
             AND created_at > NOW() - INTERVAL '60 seconds'
             AND used_at IS NULL
             LIMIT 1`,
            [user.id, channel]
        );

        if (recent.rows.length > 0) {
            return res.status(429).json({
                success: false,
                message: 'انتظر 60 ثانية قبل طلب رمز جديد'
            });
        }

        const code = crypto.randomInt(100000, 1000000).toString();
        const codeHash = await bcrypt.hash(code, 12);

        await pool.query(
            `INSERT INTO verification_codes
             (user_id, channel, code_hash, expires_at)
             VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
            [user.id, channel, codeHash]
        );

        console.log(`OTP generated for user ${user.id}: ${code}`);

        res.json({
            success: true,
            message: 'تم إنشاء رمز التحقق. سيتم إرساله عبر وسيلة التواصل المسجلة.'
        });

    } catch (error) {
        console.error('OTP ERROR:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في إنشاء رمز التحقق'
        });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, phone, code } = req.body;

        if ((!email && !phone) || !code) {
            return res.status(400).json({
                success: false,
                message: 'البريد الإلكتروني أو رقم الهاتف ورمز OTP مطلوبة'
            });
        }

        const normalizedEmail = email ? email.toLowerCase().trim() : null;
        const normalizedPhone = phone ? phone.trim() : null;
        const channel = normalizedEmail ? 'email' : 'phone';

        const userResult = await pool.query(
            'SELECT id FROM users WHERE ($1::text IS NOT NULL AND email = $1) OR ($2::text IS NOT NULL AND phone = $2) LIMIT 1',
            [normalizedEmail, normalizedPhone]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'الحساب غير موجود'
            });
        }

        const userId = userResult.rows[0].id;

        const otpResult = await pool.query(
            `SELECT id, code_hash, attempts, max_attempts
             FROM verification_codes
             WHERE user_id = $1
             AND channel = $2
             AND used_at IS NULL
             AND expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1`,
            [userId, channel]
        );

        if (otpResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'رمز OTP غير موجود أو منتهي الصلاحية'
            });
        }

        const otp = otpResult.rows[0];

        if (otp.attempts >= otp.max_attempts) {
            return res.status(429).json({
                success: false,
                message: 'تم تجاوز عدد محاولات التحقق المسموح بها'
            });
        }

        const validCode = await bcrypt.compare(
            String(code).trim(),
            otp.code_hash
        );

        if (!validCode) {
            await pool.query(
                'UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1',
                [otp.id]
            );

            return res.status(401).json({
                success: false,
                message: 'رمز OTP غير صحيح'
            });
        }

        await pool.query(
            'UPDATE verification_codes SET used_at = NOW() WHERE id = $1',
            [otp.id]
        );

        if (channel === 'email') {
            await pool.query(
                `UPDATE users
                 SET email_verified_at = NOW(),
                     account_status = 'active'
                 WHERE id = $1`,
                [userId]
            );
        } else {
            await pool.query(
                `UPDATE users
                 SET phone_verified_at = NOW(),
                     account_status = 'active'
                 WHERE id = $1`,
                [userId]
            );
        }

        res.json({
            success: true,
            message: 'تم التحقق من الحساب وتفعيله بنجاح'
        });

    } catch (error) {
        console.error('VERIFY OTP ERROR:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ أثناء التحقق من OTP'
        });
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'تم تجاوز عدد المحاولات. حاول مرة أخرى لاحقًا.'
    }
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/request-otp', authLimiter);
app.use('/api/verify-otp', authLimiter);


const nodemailer = require('nodemailer');

const mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});


app.get("/privacy", (req, res) => res.sendFile(__dirname + "/privacy.html"));
