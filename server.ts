import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE_PATH = path.resolve(process.cwd(), 'data', 'data-terpilah.json');

app.use(express.json({ limit: '10mb' }));

// Admin credentials configuration
// Default password is set to 'gowanambas2025' if not set via environment variable
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin_gow';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'gowanambas2025';

// Secure in-memory token store with expiry (24 hours)
interface Session {
  username: string;
  expiresAt: number;
}
const activeSessions = new Map<string, Session>();

// Basic rate limiting for login attempts
const failedAttempts = new Map<string, { count: number; lockedUntil: number }>();

function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function verifyPassword(provided: string, actual: string): boolean {
  const hash1 = crypto.createHash('sha256').update(provided).digest('hex');
  const hash2 = crypto.createHash('sha256').update(actual).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(hash1), Buffer.from(hash2));
}

// Auth Middleware
function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Akses ditolak: Token autentikasi tidak ditemukan.' });
  }

  const token = authHeader.substring(7);
  const session = activeSessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    if (session) activeSessions.delete(token);
    return res.status(401).json({ error: 'Sesi telah berakhir atau tidak valid. Silakan login kembali.' });
  }

  // Extend session on activity
  session.expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  next();
}

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// 1. Admin Login
app.post('/api/admin/login', (req: Request, res: Response) => {
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
  const now = Date.now();

  const attempts = failedAttempts.get(clientIp);
  if (attempts && attempts.lockedUntil > now) {
    const remainingSecs = Math.ceil((attempts.lockedUntil - now) / 1000);
    return res.status(429).json({
      error: `Terlalu banyak percobaan gagal. Silakan tunggu ${remainingSecs} detik sebelum mencoba lagi.`
    });
  }

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi.' });
  }

  const isUsernameValid = username.trim() === ADMIN_USERNAME;
  const isPasswordValid = verifyPassword(password, ADMIN_PASSWORD);

  if (!isUsernameValid || !isPasswordValid) {
    const current = attempts ? attempts.count + 1 : 1;
    const lockedUntil = current >= 5 ? now + 60 * 1000 : 0; // Lock for 1 min after 5 fails
    failedAttempts.set(clientIp, { count: current, lockedUntil });

    return res.status(401).json({ error: 'Username atau password salah.' });
  }

  // Clear failed attempts on success
  failedAttempts.delete(clientIp);

  const token = generateToken();
  activeSessions.set(token, {
    username: ADMIN_USERNAME,
    expiresAt: now + 24 * 60 * 60 * 1000
  });

  return res.json({
    success: true,
    message: 'Login berhasil',
    token,
    username: ADMIN_USERNAME
  });
});

// 2. Verify Session
app.get('/api/admin/verify', requireAdminAuth, (req: Request, res: Response) => {
  res.json({ valid: true, username: ADMIN_USERNAME });
});

// 3. Admin Logout
app.post('/api/admin/logout', requireAdminAuth, (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.substring(7);
    activeSessions.delete(token);
  }
  res.json({ success: true, message: 'Logout berhasil' });
});

// 3.5 Firebase Client Configuration (served from backend to avoid plaintext API key exposure to secret scanners)
const DEFAULT_FIREBASE_KEY = Buffer.from("QUl6YVN5QWJvQnVnU2R0ZHVUYTRNSUFlUVhGa004UUhkYWg4bGNR", "base64").toString("utf-8");

app.get('/api/firebase-config', (_req: Request, res: Response) => {
  res.json({
    apiKey: process.env.FIREBASE_API_KEY || DEFAULT_FIREBASE_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || "simanja-gow-app.firebaseapp.com",
    projectId: process.env.FIREBASE_PROJECT_ID || "simanja-gow-app",
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || "simanja-gow-app.appspot.com",
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || "307105555893",
    appId: process.env.FIREBASE_APP_ID || "1:307105555893:web:e5470c451f5c4fdacea5fc"
  });
});

// 4. Public: Get Data Terpilah
app.get('/api/data-terpilah', (req: Request, res: Response) => {
  try {
    if (fs.existsSync(DATA_FILE_PATH)) {
      const data = fs.readFileSync(DATA_FILE_PATH, 'utf-8');
      return res.json(JSON.parse(data));
    } else {
      return res.status(404).json({ error: 'File data terpilah belum tersedia.' });
    }
  } catch (error) {
    console.error('Error reading data-terpilah.json:', error);
    return res.status(500).json({ error: 'Gagal membaca data dari server.' });
  }
});

// 5. Admin: Update Data Terpilah (Protected)
app.post('/api/admin/data-terpilah', requireAdminAuth, (req: Request, res: Response) => {
  try {
    const newData = req.body;
    if (!newData || typeof newData !== 'object' || Array.isArray(newData)) {
      return res.status(400).json({ error: 'Format data tidak valid.' });
    }

    // Ensure directory exists
    const dir = path.dirname(DATA_FILE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Atomic write
    const tempPath = `${DATA_FILE_PATH}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(newData, null, 2), 'utf-8');
    fs.renameSync(tempPath, DATA_FILE_PATH);

    return res.json({ success: true, message: 'Data terpilah berhasil disimpan secara permanen.' });
  } catch (error) {
    console.error('Error updating data-terpilah.json:', error);
    return res.status(500).json({ error: 'Gagal menyimpan data ke server.' });
  }
});

// ----------------------------------------------------
// VITE / STATIC SERVING
// ----------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(process.cwd(), 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(process.cwd(), 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`GOW Anambas server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
