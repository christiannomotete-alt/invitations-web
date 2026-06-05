const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const multer = require("multer");
const PDFDocument = require("pdfkit");
const XLSX = require("xlsx");

const config = require("./config");
const { db, initSchema, repairGuestsPhoneData } = require("./db");
const {
  randomToken,
  normalizePhone,
  extractPhoneFromText,
  hashPassword,
  verifyPassword,
  sanitizeEventType,
  getEventTypeMeta,
  baseUrl,
  isPublicHttpsUrl,
  buildEnvelopeMessage,
  parseGuests,
  parseGuestsCsv,
  csvCell
} = require("./utils");
const {
  sendWhatsAppTextMessage,
  sendWhatsAppTemplateMessage,
  sendWhatsAppImageMessage
} = require("./whatsapp");

const {
  GOOGLE_OAUTH_ENABLED,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL,
  WHATSAPP_AUTO_ENABLED,
  WHATSAPP_ACCESS_TOKEN,
  WHATSAPP_PHONE_NUMBER_ID,
  WHATSAPP_API_VERSION,
  WHATSAPP_TEMPLATE_NAME,
  WHATSAPP_TEMPLATE_LANGUAGE,
  WHATSAPP_TEMPLATE_FALLBACK_NAME,
  WHATSAPP_TEMPLATE_FALLBACK_LANGUAGE,
  WHATSAPP_TEMPLATE_PARAM_MODE,
  WHATSAPP_ENVELOPE_IMAGE_MODE,
  WHATSAPP_ENVELOPE_IMAGE_URL,
  WHATSAPP_ENVELOPE_IMAGE_CAPTION,
  APP_BASE_URL,
  EVENT_TYPES,
  INVITATION_TEMPLATES,
  THEME_ACCENTS,
  THEME_FONTS,
  THEME_STYLES,
  PORT,
  isProduction
} = config;

const app = express();
const ROOT = __dirname;
const PUBLIC_DIR = config.PUBLIC_DIR;
const DATA_DIR = config.DATA_DIR;
const UPLOADS_DIR = config.UPLOADS_DIR;
const LOGS_DIR = config.LOGS_DIR;
const WHATSAPP_LOG_PATH = path.join(LOGS_DIR, "whatsapp-send.log");
const CSRF_TOKEN_KEY = "_csrfToken";
const LOGIN_ATTEMPT_LIMIT = 6;
const LOGIN_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_DURATION_MS = 20 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(LOGS_DIR, { recursive: true });

initSchema();
repairGuestsPhoneData(db, extractPhoneFromText);

app.set("view engine", "ejs");
app.set("views", config.VIEWS_DIR);

if (isProduction) {
  app.set("trust proxy", 1);
}

app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

app.use(
  session({
    secret: process.env.SESSION_SECRET || config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

function appendWhatsAppLogLine(line) {
  try {
    fs.appendFileSync(WHATSAPP_LOG_PATH, `${line}\n`, "utf8");
  } catch (error) {
    console.error("[whatsapp-log] append failed:", error?.message || error);
  }
}

function getClientIp(req) {
  return String(req.ip || req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown");
}

function getSessionCsrfToken(req) {
  if (!req.session[CSRF_TOKEN_KEY]) {
    req.session[CSRF_TOKEN_KEY] = randomToken(24);
  }
  return req.session[CSRF_TOKEN_KEY];
}

function csrfProtection(req, res, next) {
  res.locals.csrfToken = getSessionCsrfToken(req);
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  const token = String(req.body?._csrf || req.query?._csrf || req.headers["x-csrf-token"] || "");
  if (!token || token !== req.session[CSRF_TOKEN_KEY]) {
    return res.status(403).send("Jeton CSRF invalide.");
  }
  return next();
}

function createRateLimiter({ windowMs, max, keyFn, message }) {
  const hits = new Map();
  return (req, res, next) => {
    const key = keyFn(req);
    const now = Date.now();
    const current = hits.get(key);
    if (!current || current.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    current.count += 1;
    if (current.count > max) {
      const waitSec = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      return res.status(429).send(`${message} Reessayez dans ${waitSec}s.`);
    }
    return next();
  };
}

const loginAttemptState = new Map();

function getLoginAttemptKey(req, email) {
  return `${String(email || "").trim().toLowerCase()}|${getClientIp(req)}`;
}

function getLoginBlockState(req, email) {
  const key = getLoginAttemptKey(req, email);
  const now = Date.now();
  const entry = loginAttemptState.get(key);
  if (!entry) return { blocked: false, key };
  if (entry.lockUntil && entry.lockUntil > now) {
    return { blocked: true, key, waitMs: entry.lockUntil - now };
  }
  if (entry.windowStart + LOGIN_ATTEMPT_WINDOW_MS <= now) {
    loginAttemptState.delete(key);
    return { blocked: false, key };
  }
  return { blocked: false, key };
}

function registerLoginFailure(key) {
  const now = Date.now();
  const entry = loginAttemptState.get(key);
  if (!entry || entry.windowStart + LOGIN_ATTEMPT_WINDOW_MS <= now) {
    loginAttemptState.set(key, { count: 1, windowStart: now, lockUntil: 0 });
    return;
  }
  entry.count += 1;
  if (entry.count >= LOGIN_ATTEMPT_LIMIT) {
    entry.lockUntil = now + LOGIN_LOCK_DURATION_MS;
  }
}

function clearLoginFailures(req, email) {
  const key = getLoginAttemptKey(req, email);
  loginAttemptState.delete(key);
}

function normalizeIsoDateInput(raw) {
  const value = String(raw || "").trim();
  if (!value) return null;
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : null;
}

function daysUntilIsoDate(isoDate) {
  const match = String(isoDate || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const targetUtc = Date.UTC(year, month - 1, day);
  const now = new Date();
  const todayUtc = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.floor((targetUtc - todayUtc) / (24 * 60 * 60 * 1000));
}

function decodeUploadedCsv(file) {
  if (!file) return "";
  try {
    if (file.buffer) {
      return file.buffer.toString("utf8").replace(/^\uFEFF/, "");
    }
    if (file.path && fs.existsSync(file.path)) {
      return fs.readFileSync(file.path, "utf8").replace(/^\uFEFF/, "");
    }
  } catch {
    return "";
  }
  return "";
}

function normalizeImportHeader(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "");
}

function pickImportValue(row, candidates) {
  for (const candidate of candidates) {
    const value = row[candidate];
    if (value !== undefined && value !== null && String(value).trim()) return String(value).trim();
  }
  return "";
}

function normalizeImportRows(rawRows) {
  const rows = [];
  for (const raw of rawRows) {
    const row = {};
    for (const [key, value] of Object.entries(raw || {})) {
      row[normalizeImportHeader(key)] = value;
    }
    const fullName = pickImportValue(row, ["nom", "name", "fullname", "fullName", "invite", "guest", "prenomnom"]);
    const phoneRaw = pickImportValue(row, ["numero", "telephone", "phone", "tel", "whatsapp", "mobile"]);
    const tableName = pickImportValue(row, ["table", "tablename", "nomtable"]);
    const seatLabel = pickImportValue(row, ["place", "seat", "siege"]);
    const category = pickImportValue(row, ["categorie", "category", "groupe", "group"]);
    const maxPlusOnesRaw = pickImportValue(row, ["accompagnants", "plusone", "plusones", "maxplusones"]);
    const phone = normalizePhone(phoneRaw);
    const maxPlusOnes = parseOptionalInteger(maxPlusOnesRaw, { min: 0, max: 9 });
    if (!fullName) continue;
    rows.push({
      fullName,
      phone: phone.length >= 8 ? phone : null,
      tableName: tableName || null,
      seatLabel: seatLabel || null,
      category: category || null,
      maxPlusOnes: maxPlusOnes ?? 1
    });
  }
  return rows;
}

function parseGuestsSpreadsheet(file) {
  if (!file?.path) return [];
  const workbook = XLSX.readFile(file.path);
  const firstSheetName = workbook.SheetNames[0];
  if (!firstSheetName) return [];
  const rows = XLSX.utils.sheet_to_json(workbook.Sheets[firstSheetName], { defval: "" });
  return normalizeImportRows(rows);
}

function parseGuestsCsvAdvanced(rawCsv) {
  const lines = String(rawCsv || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) return [];
  const separator = lines[0].includes(";") ? ";" : ",";
  const headers = lines[0].split(separator).map((header) => normalizeImportHeader(header));
  const rows = [];
  for (let i = 1; i < lines.length; i += 1) {
    const values = lines[i].split(separator).map((value) => value.trim());
    const row = {};
    headers.forEach((header, index) => {
      row[header] = values[index] || "";
    });
    rows.push(row);
  }
  return normalizeImportRows(rows);
}

function mergeGuests(...groups) {
  const map = new Map();
  for (const group of groups) {
    for (const guest of group || []) {
      const fullName = String(guest.fullName || "").trim();
      const phoneRaw = String(guest.phone || "").trim();
      const phone = phoneRaw ? normalizePhone(phoneRaw) : null;
      if (!fullName) continue;
      const normalizedPhone = phone && phone.length >= 8 ? phone : null;
      const key = `${fullName.toLowerCase()}|${normalizedPhone || "-"}`;
      if (!map.has(key)) {
        map.set(key, { fullName, phone: normalizedPhone });
      }
    }
  }
  return Array.from(map.values());
}

function sanitizeTemplateKey(value) {
  const normalized = String(value || "").trim();
  return INVITATION_TEMPLATES.some((item) => item.value === normalized) ? normalized : "";
}

function sanitizeChoice(value, choices, fallback) {
  const normalized = String(value || "").trim();
  return choices.some((item) => item.value === normalized) ? normalized : fallback;
}

function parseOptionalInteger(value, { min = 0, max = 10000 } = {}) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed)) return null;
  return Math.min(max, Math.max(min, parsed));
}

function compactText(value, max = 1000) {
  const text = String(value || "").trim();
  return text ? text.slice(0, max) : null;
}

function sanitizeHttpUrl(value) {
  const text = compactText(value, 500);
  if (!text) return null;
  try {
    const parsed = new URL(text);
    return ["http:", "https:"].includes(parsed.protocol) ? text : null;
  } catch {
    return null;
  }
}

function cleanupUploadedFile(file) {
  try {
    if (!file?.path) return;
    if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
  } catch {
    return;
  }
}

function cleanupUnusedInvitationImage(imagePath) {
  const value = String(imagePath || "").trim();
  if (!value.startsWith("/uploads/")) return;
  const stillUsed = db.prepare("SELECT 1 FROM invitations WHERE image_path = ? LIMIT 1").get(value);
  if (stillUsed) return;
  const target = path.resolve(UPLOADS_DIR, path.basename(value));
  if (!target.startsWith(path.resolve(UPLOADS_DIR))) return;
  try {
    if (fs.existsSync(target)) fs.unlinkSync(target);
  } catch {
    return;
  }
}

function isValidUploadedImage(file) {
  if (!file?.path) return true;
  try {
    const buffer = fs.readFileSync(file.path);
    if (buffer.length < 12) return false;
    const isPng =
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47 &&
      buffer[4] === 0x0d &&
      buffer[5] === 0x0a &&
      buffer[6] === 0x1a &&
      buffer[7] === 0x0a;
    const isJpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
    const isWebp =
      buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP";
    return isPng || isJpeg || isWebp;
  } catch {
    return false;
  }
}

function updateGuestWhatsAppStatusByToken(token, status, detail) {
  db.prepare(
    `UPDATE guests
     SET whatsapp_status = ?,
         whatsapp_detail = ?,
         whatsapp_sent_at = CASE WHEN ? = 'sent' THEN CURRENT_TIMESTAMP ELSE whatsapp_sent_at END,
         last_reminder_at = CASE WHEN ? = 'reminded' THEN CURRENT_TIMESTAMP ELSE last_reminder_at END
     WHERE token = ?`
  ).run(status, String(detail || "").slice(0, 1000), status, status, token);
}

function updateGuestWhatsAppStatusById(guestId, status, detail) {
  db.prepare(
    `UPDATE guests
     SET whatsapp_status = ?,
         whatsapp_detail = ?,
         whatsapp_sent_at = CASE WHEN ? = 'sent' THEN CURRENT_TIMESTAMP ELSE whatsapp_sent_at END,
         last_reminder_at = CASE WHEN ? = 'reminded' THEN CURRENT_TIMESTAMP ELSE last_reminder_at END
     WHERE id = ?`
  ).run(status, String(detail || "").slice(0, 1000), status, status, guestId);
}

const authRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  keyFn: (req) => `auth:${getClientIp(req)}`,
  message: "Trop de tentatives sur l'authentification."
});

const rsvpRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 50,
  keyFn: (req) => `rsvp:${req.params.token}:${getClientIp(req)}`,
  message: "Trop de requetes RSVP."
});

app.use(csrfProtection);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/connexion");
  return next();
}

function getDashboardInvitations(userId, { search = "", status = "all" } = {}) {
  const normalizedStatus = ["all", "yes", "no", "pending"].includes(status) ? status : "all";
  const q = `%${String(search || "").trim().toLowerCase()}%`;
  const statusFilter =
    normalizedStatus === "yes"
      ? "AND yes_count > 0"
      : normalizedStatus === "no"
        ? "AND no_count > 0"
        : normalizedStatus === "pending"
          ? "AND pending_count > 0"
          : "";

  return db
    .prepare(
      `
      SELECT *
      FROM (
        SELECT
          i.id,
          i.event_type,
          i.couple_names,
          i.event_date,
          i.venue,
          i.created_at,
          COUNT(g.id) AS guest_count,
          SUM(CASE WHEN g.rsvp_status = 'yes' THEN 1 ELSE 0 END) AS yes_count,
          SUM(CASE WHEN g.rsvp_status = 'no' THEN 1 ELSE 0 END) AS no_count,
          SUM(CASE WHEN g.rsvp_status = 'pending' THEN 1 ELSE 0 END) AS pending_count
        FROM invitations i
        LEFT JOIN guests g ON g.invitation_id = i.id
        WHERE i.owner_user_id = ?
          AND (
            ? = '%%'
            OR LOWER(i.couple_names) LIKE ?
            OR LOWER(i.venue) LIKE ?
            OR EXISTS (
              SELECT 1
              FROM guests g2
              WHERE g2.invitation_id = i.id
                AND (
                  LOWER(g2.full_name) LIKE ?
                  OR LOWER(COALESCE(g2.phone, '')) LIKE ?
                )
            )
          )
        GROUP BY i.id
      ) agg
      WHERE 1 = 1
      ${statusFilter}
      ORDER BY created_at DESC
    `
    )
    .all(userId, q, q, q, q, q);
}

app.use((req, res, next) => {
  const userId = req.session.userId;
  if (!userId) {
    res.locals.currentUser = null;
    return next();
  }
  const user = db.prepare("SELECT id, full_name, email FROM users WHERE id = ?").get(userId);
  if (!user) {
    req.session.destroy(() => undefined);
    res.locals.currentUser = null;
    return next();
  }
  res.locals.currentUser = user;
  return next();
});

app.get(["/accueil", "/accueil.html"], (_req, res) => {
  return res.sendFile(path.join(ROOT, "accueil.html"));
});

app.get(["/invitation-mariage", "/invitation-mariage.html"], (_req, res) => {
  return res.sendFile(path.join(ROOT, "invitation-mariage.html"));
});

app.get("/index.html", (_req, res) => {
  return res.sendFile(path.join(ROOT, "index.html"));
});

app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/tableau-de-bord");
  return res.redirect("/accueil.html");
});

app.get("/inscription", (req, res) => {
  if (req.session.userId) return res.redirect("/tableau-de-bord");
  return res.render("register", { error: req.query.error || "", googleEnabled: GOOGLE_OAUTH_ENABLED });
});

app.post("/inscription", authRateLimiter, (req, res) => {
  const fullName = String(req.body.fullName || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!fullName || !email || password.length < 8) {
    return res.redirect(
      "/inscription?error=Nom%2C+email+et+mot+de+passe+%288+caracteres+minimum%29+sont+obligatoires."
    );
  }

  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (exists) return res.redirect("/inscription?error=Cet+email+est+deja+utilise.");

  const info = db
    .prepare("INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)")
    .run(fullName, email, hashPassword(password));

  req.session.userId = info.lastInsertRowid;
  return res.redirect("/tableau-de-bord");
});

app.get("/connexion", (req, res) => {
  if (req.session.userId) return res.redirect("/tableau-de-bord");
  return res.render("login", { error: req.query.error || "", googleEnabled: GOOGLE_OAUTH_ENABLED });
});

app.post("/connexion", authRateLimiter, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const blockState = getLoginBlockState(req, email);
  if (blockState.blocked) {
    const waitMin = Math.max(1, Math.ceil((blockState.waitMs || 0) / (60 * 1000)));
    return res.redirect(`/connexion?error=Compte+temporairement+verrouille.+Reessayez+dans+${waitMin}+minute(s).`);
  }
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user || !verifyPassword(password, user.password_hash)) {
    registerLoginFailure(blockState.key);
    return res.redirect("/connexion?error=Email+ou+mot+de+passe+incorrect.");
  }

  clearLoginFailures(req, email);
  req.session.userId = user.id;
  return res.redirect("/tableau-de-bord");
});

if (GOOGLE_OAUTH_ENABLED) {
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    const user = db.prepare("SELECT id, full_name, email FROM users WHERE id = ?").get(id);
    done(null, user || false);
  });

  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL
      },
      (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = String(profile.emails?.[0]?.value || "").trim().toLowerCase();
          const googleId = String(profile.id || "").trim();
          const fullName = String(profile.displayName || email || "Utilisateur Google").trim();

          if (!email || !googleId) {
            return done(null, false);
          }

          const userByGoogleId = db
            .prepare("SELECT id, full_name, email FROM users WHERE google_id = ?")
            .get(googleId);
          if (userByGoogleId) return done(null, userByGoogleId);

          const userByEmail = db
            .prepare("SELECT id, full_name, email, google_id FROM users WHERE email = ?")
            .get(email);
          if (userByEmail) {
            if (!userByEmail.google_id) {
              db.prepare("UPDATE users SET google_id = ? WHERE id = ?").run(googleId, userByEmail.id);
            }
            return done(null, {
              id: userByEmail.id,
              full_name: userByEmail.full_name,
              email: userByEmail.email
            });
          }

          const info = db
            .prepare("INSERT INTO users (full_name, email, password_hash, google_id) VALUES (?, ?, ?, ?)")
            .run(fullName, email, hashPassword(randomToken(24)), googleId);

          return done(null, { id: info.lastInsertRowid, full_name: fullName, email });
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  app.get("/auth/google", (req, res, next) => {
    return passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" })(
      req,
      res,
      next
    );
  });

  app.get("/auth/google/callback", (req, res, next) => {
    return passport.authenticate("google", { failureRedirect: "/connexion?error=Connexion+Google+echouee." })(
      req,
      res,
      () => {
        req.session.userId = req.user.id;
        return res.redirect("/tableau-de-bord");
      }
    );
  });
}

app.post("/deconnexion", (req, res) => {
  req.session.destroy(() => res.redirect("/accueil.html"));
});

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}-${randomToken(8)}${ext}`);
  }
});

const uploadInvitationAssets = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    const imageAllowed = ["image/jpeg", "image/png", "image/webp"];
    const csvAllowed = [
      "text/csv",
      "application/csv",
      "text/plain",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ];

    if (file.fieldname === "image") {
      return cb(null, imageAllowed.includes(file.mimetype));
    }
    if (file.fieldname === "guestsCsvFile") {
      const ext = path.extname(file.originalname || "").toLowerCase();
      return cb(null, csvAllowed.includes(file.mimetype) || ext === ".csv" || ext === ".xlsx");
    }
    return cb(null, false);
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.get("/tableau-de-bord", requireAuth, (req, res) => {
  const search = String(req.query.search || "").trim();
  const statusFilter = String(req.query.status || "all").trim().toLowerCase();
  return res.render("dashboard", {
    invitations: getDashboardInvitations(req.session.userId, { search, status: statusFilter }),
    eventTypes: EVENT_TYPES,
    filters: {
      search,
      status: ["all", "yes", "no", "pending"].includes(statusFilter) ? statusFilter : "all"
    },
    success: req.query.success || "",
    error: req.query.error || ""
  });
});

app.post("/tableau-de-bord/invitation/:id/supprimer", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT id, image_path FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);

  if (!invitation) {
    return res
      .status(404)
      .redirect("/tableau-de-bord?error=Invitation+introuvable+ou+acces+refuse.");
  }

  db.prepare("DELETE FROM invitations WHERE id = ?").run(invitation.id);
  cleanupUnusedInvitationImage(invitation.image_path);
  return res.redirect("/tableau-de-bord?success=Invitation+supprimee+avec+succes.");
});

app.post("/tableau-de-bord/invitation/:id/dupliquer", requireAuth, (req, res) => {
  const source = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!source) {
    return res.redirect("/tableau-de-bord?error=Invitation+introuvable+pour+duplication.");
  }

  const sourceGuests = db
    .prepare("SELECT full_name, phone, category, table_name, seat_label, max_plus_ones FROM guests WHERE invitation_id = ? ORDER BY id ASC")
    .all(source.id);

  const newInvitationId = randomToken(10);
  const newName = `${source.couple_names} (copie)`;

  const tx = db.transaction(() => {
    db.prepare(
      `INSERT INTO invitations
       (id, owner_user_id, event_type, template_key, couple_names, event_date, event_date_iso, venue, message, image_path, og_title, og_description, capacity, organizer_phone, schedule, dress_code, map_url, theme_accent, theme_font, theme_style)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      newInvitationId,
      req.session.userId,
      source.event_type,
      source.template_key || null,
      newName,
      source.event_date,
      source.event_date_iso,
      source.venue,
      source.message,
      source.image_path,
      source.og_title,
      source.og_description,
      source.capacity,
      source.organizer_phone,
      source.schedule,
      source.dress_code,
      source.map_url,
      source.theme_accent,
      source.theme_font,
      source.theme_style
    );

    const insertGuest = db.prepare(
      "INSERT INTO guests (invitation_id, full_name, phone, token, rsvp_status, plus_one, attendee_count, category, table_name, seat_label, max_plus_ones) VALUES (?, ?, ?, ?, 'pending', 0, 1, ?, ?, ?, ?)"
    );
    for (const guest of sourceGuests) {
      insertGuest.run(
        newInvitationId,
        guest.full_name,
        guest.phone || null,
        randomToken(9),
        guest.category || null,
        guest.table_name || null,
        guest.seat_label || null,
        guest.max_plus_ones ?? 1
      );
    }
  });

  tx();
  return res.redirect(`/tableau-de-bord/invitation/${newInvitationId}?success=Invitation+dupliquee+avec+succes.`);
});

app.post("/tableau-de-bord/historique/supprimer", requireAuth, (req, res) => {
  const imagePaths = db
    .prepare("SELECT DISTINCT image_path FROM invitations WHERE owner_user_id = ? AND image_path IS NOT NULL")
    .all(req.session.userId)
    .map((row) => row.image_path);
  db.prepare("DELETE FROM invitations WHERE owner_user_id = ?").run(req.session.userId);
  for (const imagePath of imagePaths) cleanupUnusedInvitationImage(imagePath);
  return res.redirect("/tableau-de-bord?success=Historique+des+invitations+supprime.");
});

app.get("/tableau-de-bord/nouvelle-invitation", requireAuth, (_req, res) => {
  return res.render("invitation-form", {
    invitation: null,
    action: "/tableau-de-bord/nouvelle-invitation",
    error: "",
    eventTypes: EVENT_TYPES,
    invitationTemplates: INVITATION_TEMPLATES,
    themeAccents: THEME_ACCENTS,
    themeFonts: THEME_FONTS,
    themeStyles: THEME_STYLES,
    selectedEventType: ""
  });
});

app.post(
  "/tableau-de-bord/nouvelle-invitation",
  requireAuth,
  uploadInvitationAssets.fields([
    { name: "image", maxCount: 1 },
    { name: "guestsCsvFile", maxCount: 1 }
  ]),
  async (req, res) => {
  const rawEventType = String(req.body.eventType || "").trim().toLowerCase();
  const eventTypeIsValid = EVENT_TYPES.some((item) => item.value === rawEventType);
  const eventType = eventTypeIsValid ? rawEventType : "mariage";
  const templateKey = sanitizeTemplateKey(req.body.templateKey);
  const coupleNames = String(req.body.coupleNames || "").trim();
  const eventDate = String(req.body.eventDate || "").trim();
  const eventDateIso = normalizeIsoDateInput(req.body.eventDateIso);
  const venue = String(req.body.venue || "").trim();
  const message = String(req.body.message || "").trim();
  const ogTitle = String(req.body.ogTitle || "").trim();
  const ogDescription = String(req.body.ogDescription || "").trim();
  const capacity = parseOptionalInteger(req.body.capacity, { min: 1, max: 50000 });
  const organizerPhone = normalizePhone(req.body.organizerPhone || "");
  const schedule = compactText(req.body.schedule, 1200);
  const dressCode = compactText(req.body.dressCode, 200);
  const mapUrl = sanitizeHttpUrl(req.body.mapUrl);
  const themeAccent = sanitizeChoice(req.body.themeAccent, THEME_ACCENTS, "bleu");
  const themeFont = sanitizeChoice(req.body.themeFont, THEME_FONTS, "sans");
  const themeStyle = sanitizeChoice(req.body.themeStyle, THEME_STYLES, "envelope");
  const imageFile = req.files?.image?.[0];
  const csvFile = req.files?.guestsCsvFile?.[0];

  if (!eventTypeIsValid || !coupleNames || !eventDate || !venue || !message) {
    cleanupUploadedFile(imageFile);
    cleanupUploadedFile(csvFile);
    return res.render("invitation-form", {
      invitation: {
        event_type: eventType,
        template_key: templateKey,
        couple_names: coupleNames,
        event_date: eventDate,
        event_date_iso: eventDateIso,
        venue,
        message,
        og_title: ogTitle,
        og_description: ogDescription,
        capacity,
        organizer_phone: organizerPhone,
        schedule,
        dress_code: dressCode,
        map_url: mapUrl,
        theme_accent: themeAccent,
        theme_font: themeFont,
        theme_style: themeStyle
      },
      action: "/tableau-de-bord/nouvelle-invitation",
      error: "Tous les champs principaux sont obligatoires, y compris le type d'invitation.",
      eventTypes: EVENT_TYPES,
      invitationTemplates: INVITATION_TEMPLATES,
      themeAccents: THEME_ACCENTS,
      themeFonts: THEME_FONTS,
      themeStyles: THEME_STYLES,
      selectedEventType: eventTypeIsValid ? eventType : ""
    });
  }

  const invitationId = randomToken(10);
  if (imageFile && !isValidUploadedImage(imageFile)) {
    cleanupUploadedFile(imageFile);
    cleanupUploadedFile(csvFile);
    return res.render("invitation-form", {
      invitation: {
        event_type: eventType,
        template_key: templateKey,
        couple_names: coupleNames,
        event_date: eventDate,
        event_date_iso: eventDateIso,
        venue,
        message,
        og_title: ogTitle,
        og_description: ogDescription,
        capacity,
        organizer_phone: organizerPhone,
        schedule,
        dress_code: dressCode,
        map_url: mapUrl,
        theme_accent: themeAccent,
        theme_font: themeFont,
        theme_style: themeStyle
      },
      action: "/tableau-de-bord/nouvelle-invitation",
      error: "Image refusee: seuls les vrais fichiers PNG, JPEG ou WebP sont acceptes.",
      eventTypes: EVENT_TYPES,
      invitationTemplates: INVITATION_TEMPLATES,
      themeAccents: THEME_ACCENTS,
      themeFonts: THEME_FONTS,
      themeStyles: THEME_STYLES,
      selectedEventType: eventType
    });
  }
  const imagePath = imageFile ? `/uploads/${imageFile.filename}` : null;
  const guestsFromText = parseGuests(req.body.guests || "");
  const guestsFromCsvText = parseGuestsCsv(req.body.guestsCsv || "");
  const guestsFromCsvFile = parseGuestsCsv(decodeUploadedCsv(csvFile));
  cleanupUploadedFile(csvFile);
  const guests = mergeGuests(guestsFromText, guestsFromCsvText, guestsFromCsvFile);

  const createdGuests = [];
  const tx = db.transaction(() => {
    db.prepare(
      `INSERT INTO invitations
       (id, owner_user_id, event_type, template_key, couple_names, event_date, event_date_iso, venue, message, image_path, og_title, og_description, capacity, organizer_phone, schedule, dress_code, map_url, theme_accent, theme_font, theme_style)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      invitationId,
      req.session.userId,
      eventType,
      templateKey || null,
      coupleNames,
      eventDate,
      eventDateIso,
      venue,
      message,
      imagePath,
      ogTitle || null,
      ogDescription || null,
      capacity,
      organizerPhone.length >= 8 ? organizerPhone : null,
      schedule,
      dressCode,
      mapUrl,
      themeAccent,
      themeFont,
      themeStyle
    );

    const guestStmt = db.prepare(
      "INSERT INTO guests (invitation_id, full_name, phone, token, max_plus_ones) VALUES (?, ?, ?, ?, 1)"
    );
    for (const guest of guests) {
      const token = randomToken(9);
      guestStmt.run(invitationId, guest.fullName, guest.phone, token);
      createdGuests.push({ ...guest, token });
    }
  });

  tx();

  let sentCount = 0;
  let failedCount = 0;
  let skippedCount = 0;
  const failedReasons = [];
  let imageSkippedCount = 0;
  const dispatchReports = [];
  const dispatchStartedAt = new Date().toISOString();

  for (const guest of createdGuests) {
    if (!guest.phone) {
      skippedCount += 1;
      updateGuestWhatsAppStatusByToken(guest.token, "skipped", "Numero manquant");
      dispatchReports.push({
        guestName: guest.fullName,
        phone: "",
        status: "SKIPPED_NO_PHONE",
        detail: "Numero manquant"
      });
      continue;
    }

    if (!WHATSAPP_AUTO_ENABLED) {
      skippedCount += 1;
      updateGuestWhatsAppStatusByToken(guest.token, "not_configured", "Envoi automatique non configure");
      dispatchReports.push({
        guestName: guest.fullName,
        phone: guest.phone,
        status: "SKIPPED_NOT_CONFIGURED",
        detail: "Envoi automatique non configure"
      });
      continue;
    }

    const rsvpUrl = `${baseUrl(req)}/rsvp/${guest.token}`;
    const text = buildEnvelopeMessage({
      guestName: guest.fullName,
      coupleNames,
      eventType,
      eventDate,
      venue,
      rsvpUrl
    });

    let result;
    let templateHeaderImageTried = false;
    let templateHeaderImageUsed = false;
    let templateHeaderImageFallback = false;
    let templateUsed = "";
    let usedFallbackTemplate = false;
    let primaryTemplateError = "";
    const useTemplateMode = WHATSAPP_TEMPLATE_NAME && WHATSAPP_TEMPLATE_NAME.trim().length > 0;
    if (useTemplateMode) {
      const params =
        WHATSAPP_TEMPLATE_PARAM_MODE === "rsvp_link_only"
          ? [rsvpUrl]
          : WHATSAPP_TEMPLATE_PARAM_MODE === "rsvp_link_and_couple"
            ? [rsvpUrl, coupleNames]
            : [];
      const invitationImage = imagePath ? `${baseUrl(req)}${imagePath}` : `${baseUrl(req)}/default-og.jpg`;
      const selectedImageUrl =
        WHATSAPP_ENVELOPE_IMAGE_MODE === "custom_url" && WHATSAPP_ENVELOPE_IMAGE_URL
          ? WHATSAPP_ENVELOPE_IMAGE_URL
          : invitationImage;
      const canUseTemplateHeaderImage =
        WHATSAPP_ENVELOPE_IMAGE_MODE !== "none" && isPublicHttpsUrl(selectedImageUrl);

      templateHeaderImageTried = canUseTemplateHeaderImage;
      result = await sendWhatsAppTemplateMessage(
        guest.phone,
        WHATSAPP_TEMPLATE_NAME,
        WHATSAPP_TEMPLATE_LANGUAGE,
        params,
        canUseTemplateHeaderImage ? { headerImageLink: selectedImageUrl } : {}
      );
      templateUsed = WHATSAPP_TEMPLATE_NAME;
      if (!result.ok) {
        primaryTemplateError = result.reason || "";
      }
      templateHeaderImageUsed = canUseTemplateHeaderImage && result.ok;

      if (!result.ok && canUseTemplateHeaderImage) {
        templateHeaderImageFallback = true;
        result = await sendWhatsAppTemplateMessage(
          guest.phone,
          WHATSAPP_TEMPLATE_NAME,
          WHATSAPP_TEMPLATE_LANGUAGE,
          params
        );
        if (result.ok) {
          templateUsed = WHATSAPP_TEMPLATE_NAME;
          primaryTemplateError = "";
        }
      }

      if (
        !result.ok &&
        WHATSAPP_TEMPLATE_FALLBACK_NAME &&
        WHATSAPP_TEMPLATE_FALLBACK_NAME !== WHATSAPP_TEMPLATE_NAME
      ) {
        usedFallbackTemplate = true;
        result = await sendWhatsAppTemplateMessage(
          guest.phone,
          WHATSAPP_TEMPLATE_FALLBACK_NAME,
          WHATSAPP_TEMPLATE_FALLBACK_LANGUAGE,
          []
        );
        if (result.ok) {
          templateUsed = WHATSAPP_TEMPLATE_FALLBACK_NAME;
        }
      }

      if (!result.ok && WHATSAPP_TEMPLATE_NAME === "hello_world") {
        result = await sendWhatsAppTextMessage(guest.phone, text);
        if (result.ok) {
          templateUsed = "text_message";
        }
      }
    } else {
      result = await sendWhatsAppTextMessage(guest.phone, text);
      if (result.ok) {
        templateUsed = "text_message";
      }
    }

    if (result.ok) {
      sentCount += 1;
      let imageStatus = "not_requested";
      if (templateHeaderImageUsed) {
        imageStatus = "embedded_in_template_header";
      } else if (templateHeaderImageFallback) {
        imageStatus = "template_header_rejected_fallback_without_header";
      } else if (!templateHeaderImageTried && WHATSAPP_ENVELOPE_IMAGE_MODE !== "none") {
        imageStatus = "not_embedded_header_url_invalid_or_not_public_https";
      }

      if (WHATSAPP_ENVELOPE_IMAGE_MODE !== "none" && !templateHeaderImageUsed) {
        const invitationImage = imagePath ? `${baseUrl(req)}${imagePath}` : `${baseUrl(req)}/default-og.jpg`;
        const selectedImageUrl =
          WHATSAPP_ENVELOPE_IMAGE_MODE === "custom_url" && WHATSAPP_ENVELOPE_IMAGE_URL
            ? WHATSAPP_ENVELOPE_IMAGE_URL
            : invitationImage;

        if (isPublicHttpsUrl(selectedImageUrl)) {
          const mediaCaption = `${WHATSAPP_ENVELOPE_IMAGE_CAPTION}\n${rsvpUrl}`;
          const imageResult = await sendWhatsAppImageMessage(guest.phone, selectedImageUrl, mediaCaption);
          if (imageStatus === "template_header_rejected_fallback_without_header") {
            imageStatus = imageResult.ok
              ? "template_header_rejected_then_image_sent_separately"
              : `template_header_rejected_and_image_failed: ${imageResult.reason || "unknown error"}`;
          } else {
            imageStatus = imageResult.ok ? "sent" : `failed: ${imageResult.reason || "unknown error"}`;
          }
        } else {
          imageSkippedCount += 1;
          if (imageStatus === "template_header_rejected_fallback_without_header") {
            imageStatus = "template_header_rejected_and_image_skipped_non_public_https_url";
          } else {
            imageStatus = "skipped_non_public_https_url";
          }
        }
      }
      dispatchReports.push({
        guestName: guest.fullName,
        phone: guest.phone,
        status: "SENT",
        detail: `Template/message envoye; template=${templateUsed || WHATSAPP_TEMPLATE_NAME}; fallback=${usedFallbackTemplate ? "yes" : "no"}; image=${imageStatus}${primaryTemplateError ? `; primary_error=${primaryTemplateError}` : ""}`
      });
      updateGuestWhatsAppStatusByToken(
        guest.token,
        "sent",
        `Envoye; template=${templateUsed || WHATSAPP_TEMPLATE_NAME}; fallback=${usedFallbackTemplate ? "yes" : "no"}; image=${imageStatus}`
      );
    } else {
      failedCount += 1;
      if (result.reason) failedReasons.push(result.reason);
      updateGuestWhatsAppStatusByToken(
        guest.token,
        "failed",
        `${result.reason || "Erreur inconnue"}${primaryTemplateError ? `; primary_error=${primaryTemplateError}` : ""}`
      );
      dispatchReports.push({
        guestName: guest.fullName,
        phone: guest.phone,
        status: "FAILED",
        detail: `${result.reason || "Erreur inconnue"}${primaryTemplateError ? `; primary_error=${primaryTemplateError}` : ""}`
      });
    }
  }

  const dispatchEndedAt = new Date().toISOString();
  appendWhatsAppLogLine(
    `[${dispatchEndedAt}] invitation=${invitationId} total=${createdGuests.length} sent=${sentCount} failed=${failedCount} skipped=${skippedCount}`
  );
  for (const report of dispatchReports) {
    const line =
      `[${dispatchEndedAt}] invitation=${invitationId} ` +
      `guest="${report.guestName}" phone="${report.phone || "-"}" status=${report.status} detail="${report.detail}"`;
    appendWhatsAppLogLine(line);
    console.log(line);
  }
  console.log(
    `[whatsapp-dispatch] invitation=${invitationId} started=${dispatchStartedAt} ended=${dispatchEndedAt} sent=${sentCount} failed=${failedCount} skipped=${skippedCount}`
  );

  const params = new URLSearchParams();
  let successMsg = "Invitation creeee avec succes.";
  if (sentCount > 0) {
    successMsg += ` ${sentCount} message(s) WhatsApp envoye(s).`;
  }
  successMsg += ` Resume envoi: ${sentCount} envoye(s), ${failedCount} echec(s), ${skippedCount} ignore(s).`;
  params.set("success", successMsg);

  const warnings = [];
  if (!WHATSAPP_AUTO_ENABLED && createdGuests.some((g) => g.phone)) {
    warnings.push(
      "Envoi automatique WhatsApp non configure (definir WHATSAPP_ACCESS_TOKEN et WHATSAPP_PHONE_NUMBER_ID)."
    );
  }
  if (failedCount > 0) {
    warnings.push(`${failedCount} envoi(s) WhatsApp ont echoue.`);
    if (failedReasons.length) {
      const sample = [...new Set(failedReasons)].slice(0, 2).join(" | ");
      warnings.push(`Detail: ${sample}`);
    }
    const failedGuests = dispatchReports
      .filter((item) => item.status === "FAILED")
      .slice(0, 3)
      .map((item) => `${item.phone || item.guestName}: ${item.detail}`);
    if (failedGuests.length) {
      warnings.push(`Numeros en echec: ${failedGuests.join(" ; ")}`);
    }
    if (failedReasons.some((reason) => reason.includes("133010"))) {
      warnings.push(
        "Meta: compte non enregistre (133010). Verifiez dans Meta > WhatsApp > API Setup que le numero emetteur est bien enregistre/actif, et en mode test ajoutez votre numero destinataire dans la liste des destinataires autorises."
      );
    }
  }
  const fallbackUsedCount = dispatchReports.filter((item) =>
    item.status === "SENT" && String(item.detail).includes("fallback=yes")
  ).length;
  if (fallbackUsedCount > 0) {
    warnings.push(
      `${fallbackUsedCount} envoi(s) ont utilise le modele de secours (${WHATSAPP_TEMPLATE_FALLBACK_NAME}).`
    );
  }
  if (skippedCount > 0 && WHATSAPP_AUTO_ENABLED) {
    warnings.push(`${skippedCount} invite(s) ignores (numero manquant).`);
  }
  if (imageSkippedCount > 0) {
    warnings.push(
      `${imageSkippedCount} media enveloppe non envoye(s): URL image non publique HTTPS (localhost non supporte par WhatsApp).`
    );
  }
  if (warnings.length) {
    warnings.push("Journal detaille: logs/whatsapp-send.log");
    params.set("error", warnings.join(" "));
  }

  return res.redirect(`/tableau-de-bord?${params.toString()}`);
});

app.get("/tableau-de-bord/invitation/:id", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const guests = db
    .prepare(
      "SELECT * FROM guests WHERE invitation_id = ? ORDER BY CASE rsvp_status WHEN 'yes' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, full_name"
    )
    .all(invitation.id)
    .map((guest) => {
      const invitationUrl = `${baseUrl(req)}/rsvp/${guest.token}`;
      const typeMeta = getEventTypeMeta(invitation.event_type);
      const text = encodeURIComponent(
        `Bonjour ${guest.full_name},\n\n${invitation.couple_names} ${typeMeta.invitePhrase}.\nDate: ${invitation.event_date}\nLieu: ${invitation.venue}\n\nConfirmez votre presence ici: ${invitationUrl}`
      );
      const phone = normalizePhone(guest.phone || "");
      return {
        ...guest,
        invitationUrl,
        whatsappLink: phone ? `https://wa.me/${phone}?text=${text}` : `https://wa.me/?text=${text}`
      };
    });

  const stats = db
    .prepare(
      `SELECT
         COUNT(*) AS guest_count,
         SUM(CASE WHEN rsvp_status = 'yes' THEN 1 ELSE 0 END) AS yes_count,
         SUM(CASE WHEN rsvp_status = 'no' THEN 1 ELSE 0 END) AS no_count,
         SUM(CASE WHEN rsvp_status = 'pending' THEN 1 ELSE 0 END) AS pending_count
       FROM guests WHERE invitation_id = ?`
    )
    .get(invitation.id);

  const guestCount = Number(stats.guest_count || 0);
  const yesCount = Number(stats.yes_count || 0);
  const noCount = Number(stats.no_count || 0);
  const pendingCount = Number(stats.pending_count || 0);
  const respondedCount = yesCount + noCount;
  const confirmedAttendees = db
    .prepare("SELECT SUM(attendee_count) AS total FROM guests WHERE invitation_id = ? AND rsvp_status = 'yes'")
    .get(invitation.id);
  const attendeeCount = Number(confirmedAttendees.total || 0);
  const capacity = Number(invitation.capacity || 0);
  const responseRate = guestCount > 0 ? Math.round((respondedCount / guestCount) * 100) : 0;
  const yesRateAmongResponses = respondedCount > 0 ? Math.round((yesCount / respondedCount) * 100) : 0;
  const capacityRate = capacity > 0 ? Math.min(100, Math.round((attendeeCount / capacity) * 100)) : 0;

  const trendRaw = db
    .prepare(
      `SELECT
         DATE(created_at) AS day,
         SUM(CASE WHEN status = 'yes' THEN 1 ELSE 0 END) AS yes_count,
         SUM(CASE WHEN status = 'no' THEN 1 ELSE 0 END) AS no_count,
         COUNT(*) AS total
       FROM rsvp_events
       WHERE invitation_id = ?
       GROUP BY DATE(created_at)
       ORDER BY day ASC
       LIMIT 30`
    )
    .all(invitation.id);

  let cumulative = 0;
  const trend = trendRaw.map((row) => {
    const total = Number(row.total || 0);
    cumulative += total;
    return {
      day: row.day,
      yesCount: Number(row.yes_count || 0),
      noCount: Number(row.no_count || 0),
      total,
      cumulative
    };
  });

  const topPendingGuests = db
    .prepare(
      `SELECT full_name, phone, created_at
       FROM guests
       WHERE invitation_id = ? AND rsvp_status = 'pending'
       ORDER BY created_at ASC, id ASC
       LIMIT 10`
    )
    .all(invitation.id);

  return res.render("invitation-manage", {
    invitation,
    guests,
    stats,
    advancedStats: {
      guestCount,
      yesCount,
      noCount,
      pendingCount,
      respondedCount,
      attendeeCount,
      capacity,
      responseRate,
      yesRateAmongResponses,
      capacityRate
    },
    trend,
    topPendingGuests,
    eventTypes: EVENT_TYPES,
    invitationTemplates: INVITATION_TEMPLATES,
    themeAccents: THEME_ACCENTS,
    themeFonts: THEME_FONTS,
    themeStyles: THEME_STYLES,
    selectedEventType: sanitizeEventType(invitation.event_type),
    success: req.query.success || "",
    error: req.query.error || ""
  });
});

app.post(
  "/tableau-de-bord/invitation/:id/modifier",
  requireAuth,
  uploadInvitationAssets.fields([
    { name: "image", maxCount: 1 },
    { name: "guestsCsvFile", maxCount: 1 }
  ]),
  (req, res) => {
    const invitation = db
      .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
      .get(req.params.id, req.session.userId);
    if (!invitation) return res.status(404).render("not-found");

    const eventType = sanitizeEventType(req.body.eventType || invitation.event_type);
    const templateKey = sanitizeTemplateKey(req.body.templateKey || invitation.template_key);
    const coupleNames = String(req.body.coupleNames || "").trim();
    const eventDate = String(req.body.eventDate || "").trim();
    const eventDateIso = normalizeIsoDateInput(req.body.eventDateIso);
    const venue = String(req.body.venue || "").trim();
    const message = String(req.body.message || "").trim();
    const ogTitle = String(req.body.ogTitle || "").trim();
    const ogDescription = String(req.body.ogDescription || "").trim();
    const capacity = parseOptionalInteger(req.body.capacity, { min: 1, max: 50000 });
    const organizerPhone = normalizePhone(req.body.organizerPhone || "");
    const schedule = compactText(req.body.schedule, 1200);
    const dressCode = compactText(req.body.dressCode, 200);
    const mapUrl = sanitizeHttpUrl(req.body.mapUrl);
    const themeAccent = sanitizeChoice(req.body.themeAccent, THEME_ACCENTS, invitation.theme_accent || "bleu");
    const themeFont = sanitizeChoice(req.body.themeFont, THEME_FONTS, invitation.theme_font || "sans");
    const themeStyle = sanitizeChoice(req.body.themeStyle, THEME_STYLES, invitation.theme_style || "envelope");
    const imageFile = req.files?.image?.[0];
    const csvFile = req.files?.guestsCsvFile?.[0];

    if (!coupleNames || !eventDate || !venue || !message) {
      cleanupUploadedFile(imageFile);
      cleanupUploadedFile(csvFile);
      return res.redirect(
        `/tableau-de-bord/invitation/${invitation.id}?error=Tous+les+champs+principaux+sont+obligatoires.`
      );
    }

    if (imageFile && !isValidUploadedImage(imageFile)) {
      cleanupUploadedFile(imageFile);
      cleanupUploadedFile(csvFile);
      return res.redirect(
        `/tableau-de-bord/invitation/${invitation.id}?error=Image+refusee:+seuls+les+vrais+fichiers+PNG,+JPEG+ou+WebP+sont+acceptes.`
      );
    }
    const imagePath = imageFile ? `/uploads/${imageFile.filename}` : invitation.image_path;
    db.prepare(
      `UPDATE invitations
       SET event_type = ?, template_key = ?, couple_names = ?, event_date = ?, event_date_iso = ?, venue = ?, message = ?, image_path = ?, og_title = ?, og_description = ?, capacity = ?, organizer_phone = ?, schedule = ?, dress_code = ?, map_url = ?, theme_accent = ?, theme_font = ?, theme_style = ?
       WHERE id = ?`
    ).run(
      eventType,
      templateKey || null,
      coupleNames,
      eventDate,
      eventDateIso,
      venue,
      message,
      imagePath,
      ogTitle || null,
      ogDescription || null,
      capacity,
      organizerPhone.length >= 8 ? organizerPhone : null,
      schedule,
      dressCode,
      mapUrl,
      themeAccent,
      themeFont,
      themeStyle,
      invitation.id
    );
    if (imageFile && invitation.image_path && invitation.image_path !== imagePath) {
      cleanupUnusedInvitationImage(invitation.image_path);
    }

    const guests = mergeGuests(
      parseGuests(req.body.newGuests || ""),
      parseGuestsCsv(req.body.guestsCsv || ""),
      parseGuestsCsv(decodeUploadedCsv(csvFile))
    );
    cleanupUploadedFile(csvFile);
    if (guests.length) {
      const tx = db.transaction(() => {
        const guestStmt = db.prepare(
          "INSERT INTO guests (invitation_id, full_name, phone, token, max_plus_ones) VALUES (?, ?, ?, ?, 1)"
        );
        for (const guest of guests) {
          guestStmt.run(invitation.id, guest.fullName, guest.phone, randomToken(9));
        }
      });
      tx();
    }

    return res.redirect(`/tableau-de-bord/invitation/${invitation.id}?success=Mise+a+jour+terminee.`);
  }
);

app.post("/tableau-de-bord/guest/:guestId/supprimer", requireAuth, (req, res) => {
  const guest = db
    .prepare(
      `SELECT g.id, g.invitation_id
       FROM guests g
       INNER JOIN invitations i ON i.id = g.invitation_id
       WHERE g.id = ? AND i.owner_user_id = ?`
    )
    .get(req.params.guestId, req.session.userId);
  if (!guest) return res.status(404).render("not-found");

  db.prepare("DELETE FROM guests WHERE id = ?").run(guest.id);
  return res.redirect(`/tableau-de-bord/invitation/${guest.invitation_id}?success=Invite+supprime.`);
  }
);

app.post("/tableau-de-bord/guest/:guestId/modifier", requireAuth, (req, res) => {
  const guest = db
    .prepare(
      `SELECT g.id, g.invitation_id
       FROM guests g
       INNER JOIN invitations i ON i.id = g.invitation_id
       WHERE g.id = ? AND i.owner_user_id = ?`
    )
    .get(req.params.guestId, req.session.userId);
  if (!guest) return res.status(404).render("not-found");

  const fullName = String(req.body.fullName || "").trim();
  const normalizedPhone = normalizePhone(req.body.phone || "");
  const phone = normalizedPhone.length >= 8 ? normalizedPhone : null;
  const category = compactText(req.body.category, 120);
  const tableName = compactText(req.body.tableName, 120);
  const seatLabel = compactText(req.body.seatLabel, 80);
  const maxPlusOnes = parseOptionalInteger(req.body.maxPlusOnes, { min: 0, max: 9 });

  if (!fullName) {
    return res.redirect(`/tableau-de-bord/invitation/${guest.invitation_id}?error=Le+nom+de+l+invite+est+obligatoire.`);
  }

  db.prepare(
    "UPDATE guests SET full_name = ?, phone = ?, category = ?, table_name = ?, seat_label = ?, max_plus_ones = ? WHERE id = ?"
  ).run(fullName, phone, category, tableName, seatLabel, maxPlusOnes ?? 1, guest.id);
  return res.redirect(`/tableau-de-bord/invitation/${guest.invitation_id}?success=Invite+mis+a+jour.`);
});

app.post("/tableau-de-bord/guest/:guestId/checkin", requireAuth, (req, res) => {
  const guest = db
    .prepare(
      `SELECT g.id, g.invitation_id
       FROM guests g
       INNER JOIN invitations i ON i.id = g.invitation_id
       WHERE g.id = ? AND i.owner_user_id = ?`
    )
    .get(req.params.guestId, req.session.userId);
  if (!guest) return res.status(404).render("not-found");

  db.prepare("UPDATE guests SET checked_in_at = COALESCE(checked_in_at, CURRENT_TIMESTAMP) WHERE id = ?").run(guest.id);
  return res.redirect(`/tableau-de-bord/invitation/${guest.invitation_id}?success=Presence+controlee.`);
});

app.get("/check-in/:token", requireAuth, (req, res) => {
  const guest = db
    .prepare(
      `SELECT g.id, g.full_name, g.invitation_id, i.owner_user_id
       FROM guests g
       INNER JOIN invitations i ON i.id = g.invitation_id
       WHERE g.token = ?`
    )
    .get(req.params.token);
  if (!guest || guest.owner_user_id !== req.session.userId) return res.status(404).render("not-found");

  db.prepare("UPDATE guests SET checked_in_at = COALESCE(checked_in_at, CURRENT_TIMESTAMP) WHERE id = ?").run(guest.id);
  return res.redirect(
    `/tableau-de-bord/invitation/${guest.invitation_id}?success=${encodeURIComponent(`Entree validee pour ${guest.full_name}.`)}`
  );
});

app.get("/tableau-de-bord/invitation/:id/scanner", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const stats = db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN checked_in_at IS NOT NULL THEN 1 ELSE 0 END) AS checked_in
       FROM guests WHERE invitation_id = ?`
    )
    .get(invitation.id);

  return res.render("qr-scanner", {
    invitation,
    stats,
    checkInBaseUrl: `${baseUrl(req)}/check-in/`
  });
});

app.post("/tableau-de-bord/invitation/:id/scanner/check-in", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT id FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).json({ ok: false, error: "Invitation introuvable." });

  const raw = String(req.body.token || req.body.code || "").trim();
  const token = raw.includes("/check-in/") ? raw.split("/check-in/").pop().split(/[?#]/)[0] : raw;
  const guest = db
    .prepare("SELECT id, full_name, checked_in_at FROM guests WHERE invitation_id = ? AND token = ?")
    .get(invitation.id, token);
  if (!guest) return res.status(404).json({ ok: false, error: "QR inconnu pour cette invitation." });

  if (!guest.checked_in_at) {
    db.prepare("UPDATE guests SET checked_in_at = CURRENT_TIMESTAMP WHERE id = ?").run(guest.id);
  }
  return res.json({
    ok: true,
    guestName: guest.full_name,
    alreadyChecked: Boolean(guest.checked_in_at)
  });
});

app.get("/tableau-de-bord/invitation/:id/apercu", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const firstGuest = db
    .prepare("SELECT * FROM guests WHERE invitation_id = ? ORDER BY id ASC LIMIT 1")
    .get(invitation.id);
  const sampleGuest = firstGuest || {
    full_name: "Invite exemple",
    token: "apercu",
    phone: ""
  };
  const rsvpUrl = firstGuest ? `${baseUrl(req)}/rsvp/${firstGuest.token}` : `${baseUrl(req)}/rsvp/apercu`;
  const message = buildEnvelopeMessage({
    guestName: sampleGuest.full_name,
    coupleNames: invitation.couple_names,
    eventType: invitation.event_type,
    eventDate: invitation.event_date,
    venue: invitation.venue,
    rsvpUrl
  });

  return res.render("invitation-preview", {
    invitation,
    guest: sampleGuest,
    rsvpUrl,
    message,
    imageUrl: invitation.image_path ? `${baseUrl(req)}${invitation.image_path}` : `${baseUrl(req)}/default-og.jpg`,
    eventTypeLabel: getEventTypeMeta(invitation.event_type).label
  });
});

app.get("/tableau-de-bord/invitation/:id/tables", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const guests = db
    .prepare("SELECT * FROM guests WHERE invitation_id = ? ORDER BY COALESCE(table_name, ''), seat_label, full_name")
    .all(invitation.id);
  const groups = new Map();
  for (const guest of guests) {
    const tableName = String(guest.table_name || "Sans table").trim() || "Sans table";
    if (!groups.has(tableName)) groups.set(tableName, []);
    groups.get(tableName).push(guest);
  }
  const tables = Array.from(groups.entries()).map(([name, rows]) => ({
    name,
    guests: rows,
    invitedCount: rows.length,
    attendeeCount: rows.reduce((sum, guest) => sum + Number(guest.rsvp_status === "yes" ? guest.attendee_count || 1 : 1), 0),
    checkedInCount: rows.filter((guest) => guest.checked_in_at).length
  }));

  return res.render("invitation-tables", {
    invitation,
    tables,
    success: req.query.success || "",
    error: req.query.error || ""
  });
});

app.post("/tableau-de-bord/invitation/:id/tables", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT id FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const assignments = String(req.body.assignments || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const guests = db.prepare("SELECT id, full_name, phone FROM guests WHERE invitation_id = ?").all(invitation.id);
  const byName = new Map(guests.map((guest) => [String(guest.full_name || "").toLowerCase(), guest]));
  const byPhone = new Map(
    guests
      .filter((guest) => guest.phone)
      .map((guest) => [normalizePhone(guest.phone || ""), guest])
  );
  const updateStmt = db.prepare(
    "UPDATE guests SET table_name = ?, seat_label = ?, category = ? WHERE id = ?"
  );
  let updated = 0;
  for (const line of assignments) {
    const [identifier, tableName = "", seatLabel = "", category = ""] = line.split(/[|;]/).map((part) => part.trim());
    if (!identifier) continue;
    const guest = byPhone.get(normalizePhone(identifier)) || byName.get(identifier.toLowerCase());
    if (!guest) continue;
    updateStmt.run(compactText(tableName, 120), compactText(seatLabel, 80), compactText(category, 120), guest.id);
    updated += 1;
  }

  return res.redirect(`/tableau-de-bord/invitation/${invitation.id}/tables?success=${updated}+affectation(s)+mise(s)+a+jour.`);
});

app.post(
  "/tableau-de-bord/invitation/:id/import/preview",
  requireAuth,
  uploadInvitationAssets.fields([{ name: "guestsCsvFile", maxCount: 1 }]),
  (req, res) => {
    const invitation = db
      .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
      .get(req.params.id, req.session.userId);
    if (!invitation) return res.status(404).render("not-found");

    const file = req.files?.guestsCsvFile?.[0];
    let rows = [];
    try {
      const ext = path.extname(file?.originalname || "").toLowerCase();
      if (file && ext === ".xlsx") {
        rows = parseGuestsSpreadsheet(file);
      } else {
        rows = parseGuestsCsvAdvanced(req.body.guestsCsv || "");
        if (file) rows = rows.concat(parseGuestsCsvAdvanced(decodeUploadedCsv(file)));
      }
    } catch (error) {
      cleanupUploadedFile(file);
      return res.redirect(
        `/tableau-de-bord/invitation/${invitation.id}?error=${encodeURIComponent(`Import impossible: ${error.message || error}`)}`
      );
    }
    cleanupUploadedFile(file);

    const existingGuests = db
      .prepare("SELECT full_name, phone FROM guests WHERE invitation_id = ?")
      .all(invitation.id);
    const existingKeys = new Set(
      existingGuests.map((guest) => `${String(guest.full_name || "").toLowerCase()}|${normalizePhone(guest.phone || "")}`)
    );
    const previewRows = rows.map((row, index) => {
      const key = `${String(row.fullName || "").toLowerCase()}|${normalizePhone(row.phone || "")}`;
      return {
        ...row,
        index,
        duplicate: existingKeys.has(key)
      };
    });

    return res.render("invitation-import-preview", {
      invitation,
      rows: previewRows,
      payload: JSON.stringify(previewRows)
    });
  }
);

app.post("/tableau-de-bord/invitation/:id/import/confirm", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT id FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  let rows = [];
  try {
    rows = JSON.parse(String(req.body.payload || "[]"));
  } catch {
    rows = [];
  }
  const selected = new Set(
    Array.isArray(req.body.selected) ? req.body.selected.map(String) : [String(req.body.selected || "")]
  );
  const toInsert = rows.filter((row) => selected.has(String(row.index)) && row.fullName && !row.duplicate);
  const tx = db.transaction(() => {
    const stmt = db.prepare(
      `INSERT INTO guests
       (invitation_id, full_name, phone, token, category, table_name, seat_label, max_plus_ones)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const row of toInsert) {
      stmt.run(
        invitation.id,
        compactText(row.fullName, 200),
        row.phone ? normalizePhone(row.phone) : null,
        randomToken(9),
        compactText(row.category, 120),
        compactText(row.tableName, 120),
        compactText(row.seatLabel, 80),
        parseOptionalInteger(row.maxPlusOnes, { min: 0, max: 9 }) ?? 1
      );
    }
  });
  tx();

  return res.redirect(`/tableau-de-bord/invitation/${invitation.id}?success=${toInsert.length}+invite(s)+importe(s).`);
});

app.get("/tableau-de-bord/invitation/:id/export.csv", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const guests = db
    .prepare("SELECT * FROM guests WHERE invitation_id = ? ORDER BY full_name")
    .all(invitation.id);
  const headers = [
    "Nom",
    "Telephone",
    "Statut RSVP",
    "Personnes",
    "Plus one",
    "Menu",
    "Allergies",
    "Commentaire",
    "Categorie",
    "Table",
    "Place",
    "WhatsApp",
    "Detail WhatsApp",
    "Envoye le",
    "Derniere relance",
    "Check-in",
    "Lien RSVP"
  ];
  const rows = guests.map((guest) => [
    guest.full_name,
    guest.phone || "",
    guest.rsvp_status,
    guest.attendee_count || 1,
    guest.plus_one ? "oui" : "non",
    guest.menu_choice || "",
    guest.allergies || "",
    guest.comment || "",
    guest.category || "",
    guest.table_name || "",
    guest.seat_label || "",
    guest.whatsapp_status || "not_sent",
    guest.whatsapp_detail || "",
    guest.whatsapp_sent_at || "",
    guest.last_reminder_at || "",
    guest.checked_in_at || "",
    `${baseUrl(req)}/rsvp/${guest.token}`
  ]);
  const csv = [headers, ...rows].map((row) => row.map(csvCell).join(";")).join("\r\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename=\"invites-${invitation.id}.csv\"`);
  return res.send(`\uFEFF${csv}`);
});

app.post("/tableau-de-bord/invitation/:id/relancer", requireAuth, async (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const scope = String(req.body.scope || "pending").trim();
  const filter =
    scope === "failed"
      ? "AND whatsapp_status = 'failed'"
      : scope === "all"
        ? ""
        : "AND rsvp_status = 'pending'";
  const guests = db
    .prepare(`SELECT * FROM guests WHERE invitation_id = ? ${filter} ORDER BY full_name`)
    .all(invitation.id);

  let sent = 0;
  let failed = 0;
  let skipped = 0;

  for (const guest of guests) {
    const phone = normalizePhone(guest.phone || "");
    if (phone.length < 8) {
      skipped += 1;
      updateGuestWhatsAppStatusById(guest.id, "skipped", "Relance ignoree: numero manquant");
      continue;
    }
    if (!WHATSAPP_AUTO_ENABLED) {
      skipped += 1;
      updateGuestWhatsAppStatusById(guest.id, "not_configured", "Relance impossible: WhatsApp non configure");
      continue;
    }

    const rsvpUrl = `${baseUrl(req)}/rsvp/${guest.token}`;
    const text = buildEnvelopeMessage({
      guestName: guest.full_name,
      coupleNames: invitation.couple_names,
      eventType: invitation.event_type,
      eventDate: invitation.event_date,
      venue: invitation.venue,
      rsvpUrl
    });
    const result = await sendWhatsAppTextMessage(phone, `Petit rappel RSVP:\n\n${text}`);
    if (result.ok) {
      sent += 1;
      updateGuestWhatsAppStatusById(guest.id, "reminded", "Relance WhatsApp envoyee");
    } else {
      failed += 1;
      updateGuestWhatsAppStatusById(guest.id, "failed", `Relance echouee: ${result.reason || "Erreur inconnue"}`);
    }
  }

  appendWhatsAppLogLine(
    `[${new Date().toISOString()}] manual-reminder invitation=${invitation.id} scope=${scope} sent=${sent} failed=${failed} skipped=${skipped}`
  );
  const params = new URLSearchParams({
    success: `Relance terminee: ${sent} envoye(s), ${failed} echec(s), ${skipped} ignore(s).`
  });
  if (!WHATSAPP_AUTO_ENABLED) {
    params.set("error", "WhatsApp automatique n'est pas configure.");
  }
  return res.redirect(`/tableau-de-bord/invitation/${invitation.id}?${params.toString()}`);
});

app.get("/tableau-de-bord/guest/:guestId/qr.svg", requireAuth, async (req, res) => {
  const guest = db
    .prepare(
      `SELECT g.id, g.token, g.invitation_id
       FROM guests g
       INNER JOIN invitations i ON i.id = g.invitation_id
       WHERE g.id = ? AND i.owner_user_id = ?`
    )
    .get(req.params.guestId, req.session.userId);
  if (!guest) return res.status(404).render("not-found");

  try {
    const QRCode = require("qrcode");
    const svg = await QRCode.toString(`${baseUrl(req)}/check-in/${guest.token}`, {
      type: "svg",
      margin: 1,
      width: 280
    });
    res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    return res.send(svg);
  } catch (error) {
    return res
      .status(503)
      .send("Generation QR indisponible. Installez les dependances avec npm install pour activer qrcode.");
  }
});

app.get("/tableau-de-bord/invitation/:id/pdf", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const guests = db
    .prepare("SELECT * FROM guests WHERE invitation_id = ? ORDER BY full_name")
    .all(invitation.id);

  function formatDateTime(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString("fr-FR", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });
  }

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename=\"invites-${invitation.id}.pdf\"`);

  const doc = new PDFDocument({ margin: 40 });
  doc.pipe(res);
  doc.fontSize(20).text("Liste des invites", { underline: true });
  doc.moveDown(0.7);
  doc.fontSize(12).text(`Couple: ${invitation.couple_names}`);
  doc.text(`Date: ${invitation.event_date}`);
  doc.text(`Lieu: ${invitation.venue}`);
  doc.text(`ID invitation: ${invitation.id}`);
  doc.moveDown();
  doc.text(`Total invites: ${guests.length}`);
  doc.text(`Confirmes: ${guests.filter((g) => g.rsvp_status === "yes").length}`);
  doc.text(`Absents: ${guests.filter((g) => g.rsvp_status === "no").length}`);
  doc.moveDown(1.2);

  const tableTop = doc.y;
  const left = doc.page.margins.left;
  const tableWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const colRatios = [0.34, 0.23, 0.23, 0.2];
  const colWidths = colRatios.map((r) => r * tableWidth);
  const rowHeight = 22;
  const headerHeight = 24;
  const bottomLimit = doc.page.height - doc.page.margins.bottom;

  function drawHeader(y) {
    const headers = ["Nom", "Date invitation", "Date approbation", "Statut"];
    let x = left;
    doc.rect(left, y, tableWidth, headerHeight).fillAndStroke("#e9eefb", "#b9c7ea");
    doc.fillColor("#1d2f5d").font("Helvetica-Bold").fontSize(10);
    headers.forEach((text, idx) => {
      doc.text(text, x + 6, y + 7, { width: colWidths[idx] - 12, align: "left" });
      x += colWidths[idx];
    });
    doc.fillColor("#000");
    doc.font("Helvetica").fontSize(9.5);
  }

  function drawRow(y, values) {
    let x = left;
    values.forEach((value, idx) => {
      doc.rect(x, y, colWidths[idx], rowHeight).stroke("#d2d9ef");
      doc.text(String(value), x + 6, y + 6, { width: colWidths[idx] - 12, align: "left" });
      x += colWidths[idx];
    });
  }

  let y = tableTop;
  drawHeader(y);
  y += headerHeight;

  for (const guest of guests) {
    if (y + rowHeight > bottomLimit) {
      doc.addPage();
      y = doc.page.margins.top;
      drawHeader(y);
      y += headerHeight;
    }
    const status =
      guest.rsvp_status === "yes" ? "Present" : guest.rsvp_status === "no" ? "Absent" : "En attente";
    drawRow(y, [
      guest.full_name || "-",
      formatDateTime(guest.created_at),
      formatDateTime(guest.responded_at),
      status
    ]);
    y += rowHeight;
  }

  doc.end();
});

app.get("/rsvp/:token", rsvpRateLimiter, (req, res) => {
  const data = db
    .prepare(
      `SELECT
         g.id AS guest_id,
         g.full_name,
         g.phone,
         g.rsvp_status,
         g.plus_one,
         g.attendee_count,
         g.max_plus_ones,
         g.menu_choice,
         g.allergies,
         g.comment,
         g.responded_at,
         i.id AS invitation_id,
         i.event_type,
         i.couple_names,
         i.event_date,
         i.venue,
         i.message,
         i.image_path,
         i.og_title,
         i.og_description,
         i.organizer_phone,
         i.schedule,
         i.dress_code,
         i.map_url,
         i.theme_accent,
         i.theme_font,
         i.theme_style
       FROM guests g
       INNER JOIN invitations i ON i.id = g.invitation_id
       WHERE g.token = ?`
    )
    .get(req.params.token);

  if (!data) return res.status(404).render("not-found");
  return res.render("rsvp", {
    data,
    eventTypeLabel: getEventTypeMeta(data.event_type).label,
    token: req.params.token,
    success: req.query.success || "",
    pageUrl: `${baseUrl(req)}/rsvp/${req.params.token}`,
    imageUrl: data.image_path ? `${baseUrl(req)}${data.image_path}` : `${baseUrl(req)}/default-og.jpg`,
    ogTitle: data.og_title || `Invitation de ${data.couple_names}`,
    ogDescription:
      data.og_description ||
      `${data.couple_names} vous invitent - ${data.event_date}, ${data.venue}`
  });
});

app.post("/rsvp/:token", rsvpRateLimiter, async (req, res) => {
  const status = req.body.status === "yes" ? "yes" : req.body.status === "no" ? "no" : null;
  if (!status) return res.redirect(`/rsvp/${req.params.token}`);

  const guest = db.prepare("SELECT * FROM guests WHERE token = ?").get(req.params.token);
  if (!guest) return res.status(404).render("not-found");

  const requestedPlusOne = req.body.plusOne === "yes" ? 1 : 0;
  const parsedAttendeeCount = Number.parseInt(String(req.body.attendeeCount || ""), 10);
  const maxAttendeeCount = Math.max(1, Math.min(10, Number(guest.max_plus_ones || 1) + 1));
  const attendeeCount = Number.isInteger(parsedAttendeeCount)
    ? Math.min(maxAttendeeCount, Math.max(1, parsedAttendeeCount))
    : requestedPlusOne
      ? Math.min(2, maxAttendeeCount)
      : 1;
  const plusOne = requestedPlusOne || attendeeCount > 1 ? 1 : 0;
  const allowedMenus = new Set(["standard", "vegetarien", "vegan", "halal", "sans-gluten", "autre"]);
  const menuChoiceRaw = String(req.body.menuChoice || "").trim().toLowerCase();
  const menuChoice = allowedMenus.has(menuChoiceRaw) ? menuChoiceRaw : null;
  const allergies = String(req.body.allergies || "").trim().slice(0, 500);
  const comment = String(req.body.comment || "").trim().slice(0, 700);

  const tx = db.transaction(() => {
    db.prepare(
      `UPDATE guests
       SET rsvp_status = ?,
           responded_at = CURRENT_TIMESTAMP,
           plus_one = ?,
           attendee_count = ?,
           menu_choice = ?,
           allergies = ?,
           comment = ?
       WHERE id = ?`
    ).run(
      status,
      plusOne,
      attendeeCount,
      status === "yes" ? menuChoice : null,
      status === "yes" ? allergies || null : null,
      comment || null,
      guest.id
    );
    db.prepare("INSERT INTO rsvp_events (invitation_id, guest_id, status) VALUES (?, ?, ?)").run(
      guest.invitation_id,
      guest.id,
      status
    );
  });
  tx();

  const invitation = db
    .prepare("SELECT couple_names, organizer_phone FROM invitations WHERE id = ?")
    .get(guest.invitation_id);
  const organizerPhone = normalizePhone(invitation?.organizer_phone || "");
  if (organizerPhone.length >= 8 && WHATSAPP_AUTO_ENABLED) {
    const statusLabel = status === "yes" ? "present" : "absent";
    const notification =
      `Nouvelle reponse RSVP pour ${invitation.couple_names}:\n` +
      `${guest.full_name} a repondu: ${statusLabel}.\n` +
      `Personnes: ${attendeeCount}`;
    sendWhatsAppTextMessage(organizerPhone, notification).catch((error) => {
      appendWhatsAppLogLine(
        `[${new Date().toISOString()}] organizer-notification failed guest=${guest.id} error=${String(error?.message || error)}`
      );
    });
  }

  return res.redirect(`/rsvp/${req.params.token}?success=Votre+reponse+a+ete+enregistree.`);
});

let reminderDispatchInProgress = false;

async function dispatchPendingRsvpReminders() {
  if (!WHATSAPP_AUTO_ENABLED) return;
  if (reminderDispatchInProgress) return;
  const base = String(APP_BASE_URL || "").trim().replace(/\/$/, "");
  if (!base) return;

  reminderDispatchInProgress = true;
  try {
    const startedAt = new Date().toISOString();
    let sent = 0;
    let failed = 0;

    const rows = db
      .prepare(
        `SELECT
           g.id AS guest_id,
           g.full_name,
           g.phone,
           g.token,
           i.id AS invitation_id,
           i.event_type,
           i.couple_names,
           i.event_date,
           i.event_date_iso,
           i.venue
         FROM guests g
         INNER JOIN invitations i ON i.id = g.invitation_id
         WHERE g.rsvp_status = 'pending'
           AND g.phone IS NOT NULL
           AND TRIM(g.phone) <> ''
           AND i.event_date_iso IS NOT NULL
           AND TRIM(i.event_date_iso) <> ''`
      )
      .all();

    const insertReminderStmt = db.prepare(
      "INSERT INTO reminder_events (invitation_id, guest_id, reminder_key, whatsapp_status, detail) VALUES (?, ?, ?, 'pending', ?)"
    );
    const finalizeReminderStmt = db.prepare(
      "UPDATE reminder_events SET whatsapp_status = ?, detail = ? WHERE guest_id = ? AND reminder_key = ?"
    );

    for (const row of rows) {
      const days = daysUntilIsoDate(row.event_date_iso);
      const reminderKey = days === 7 ? "J-7" : days === 3 ? "J-3" : null;
      if (!reminderKey) continue;

      const phone = normalizePhone(row.phone || "");
      if (phone.length < 8) continue;

      try {
        insertReminderStmt.run(
          row.invitation_id,
          row.guest_id,
          reminderKey,
          `En cours d'envoi ${reminderKey} (${startedAt}).`
        );
      } catch {
        continue;
      }

      const typeMeta = getEventTypeMeta(row.event_type);
      const rsvpUrl = `${base}/rsvp/${row.token}`;
      const reminderText =
        `Rappel ${reminderKey}: ${row.couple_names} ${typeMeta.invitePhrase}.\n` +
        `Date: ${row.event_date}\n` +
        `Lieu: ${row.venue}\n` +
        `Lien RSVP: ${rsvpUrl}`;

      try {
        const result = await sendWhatsAppTextMessage(phone, reminderText);
        if (result.ok) {
          sent += 1;
          finalizeReminderStmt.run("sent", `Envoye ${new Date().toISOString()}`, row.guest_id, reminderKey);
        } else {
          failed += 1;
          finalizeReminderStmt.run(
            "failed",
            `Echec ${new Date().toISOString()} :: ${result.error || "unknown"}`,
            row.guest_id,
            reminderKey
          );
        }
      } catch (error) {
        failed += 1;
        finalizeReminderStmt.run(
          "failed",
          `Exception ${new Date().toISOString()} :: ${String(error?.message || error)}`,
          row.guest_id,
          reminderKey
        );
      }
    }

    const endedAt = new Date().toISOString();
    appendWhatsAppLogLine(`[${endedAt}] reminders started=${startedAt} sent=${sent} failed=${failed}`);
  } finally {
    reminderDispatchInProgress = false;
  }
}

app.get("/sante", (_req, res) => {
  return res.json({ ok: true, now: new Date().toISOString() });
});

app.get("/sante/whatsapp", (_req, res) => {
  return res.json({
    enabled: WHATSAPP_AUTO_ENABLED,
    apiVersion: WHATSAPP_API_VERSION,
    phoneNumberId: WHATSAPP_PHONE_NUMBER_ID || null,
    hasAccessToken: Boolean(WHATSAPP_ACCESS_TOKEN)
  });
});

app.get("/sante/whatsapp-meta", async (_req, res) => {
  if (!WHATSAPP_AUTO_ENABLED) {
    return res.status(400).json({
      ok: false,
      reason: "whatsapp_not_configured"
    });
  }

  try {
    const endpoint = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}?fields=id,display_phone_number,verified_name,code_verification_status,quality_rating`;
    const response = await fetch(endpoint, {
      headers: {
        Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`
      }
    });
    const payload = await response.json();
    return res.status(response.status).json({
      ok: response.ok,
      status: response.status,
      data: payload
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      reason: String(error?.message || error)
    });
  }
});

if (WHATSAPP_AUTO_ENABLED && APP_BASE_URL) {
  setTimeout(() => {
    dispatchPendingRsvpReminders().catch((error) => {
      appendWhatsAppLogLine(`[${new Date().toISOString()}] reminders startup error=${String(error?.message || error)}`);
    });
  }, 15000);

  setInterval(() => {
    dispatchPendingRsvpReminders().catch((error) => {
      appendWhatsAppLogLine(`[${new Date().toISOString()}] reminders interval error=${String(error?.message || error)}`);
    });
  }, 6 * 60 * 60 * 1000);
}

app.use((_req, res) => res.status(404).render("not-found"));

app.listen(PORT, () => {
  console.log(`Serveur actif sur http://localhost:${PORT}`);
});
