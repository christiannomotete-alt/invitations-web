const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const multer = require("multer");
const Database = require("better-sqlite3");
const PDFDocument = require("pdfkit");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const GOOGLE_CREDENTIALS_PATH =
  process.env.GOOGLE_CREDENTIALS_PATH || path.join(ROOT, "google-oauth-client.json");
const WHATSAPP_CONFIG_PATH =
  process.env.WHATSAPP_CONFIG_PATH || path.join(ROOT, "whatsapp-config.json");
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, "data"));
const UPLOADS_DIR = path.resolve(process.env.UPLOADS_DIR || path.join(PUBLIC_DIR, "uploads"));
const DB_PATH = path.join(DATA_DIR, "invitation.db");
const LOGS_DIR = path.join(ROOT, "logs");
const WHATSAPP_LOG_PATH = path.join(LOGS_DIR, "whatsapp-send.log");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(LOGS_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY,
  owner_user_id INTEGER NOT NULL,
  event_type TEXT NOT NULL DEFAULT 'mariage',
  couple_names TEXT NOT NULL,
  event_date TEXT NOT NULL,
  venue TEXT NOT NULL,
  message TEXT NOT NULL,
  image_path TEXT,
  og_title TEXT,
  og_description TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS guests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id TEXT NOT NULL,
  full_name TEXT NOT NULL,
  phone TEXT,
  token TEXT UNIQUE NOT NULL,
  rsvp_status TEXT NOT NULL DEFAULT 'pending' CHECK (rsvp_status IN ('pending', 'yes', 'no')),
  responded_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(invitation_id) REFERENCES invitations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rsvp_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id TEXT NOT NULL,
  guest_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('yes', 'no')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(invitation_id) REFERENCES invitations(id) ON DELETE CASCADE,
  FOREIGN KEY(guest_id) REFERENCES guests(id) ON DELETE CASCADE
);
`);

function ensureUsersGoogleColumn() {
  const columns = db.prepare("PRAGMA table_info(users)").all();
  const hasGoogleId = columns.some((col) => col.name === "google_id");
  if (!hasGoogleId) {
    db.exec("ALTER TABLE users ADD COLUMN google_id TEXT");
  }
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL");
}

ensureUsersGoogleColumn();

function ensureInvitationEventTypeColumn() {
  const columns = db.prepare("PRAGMA table_info(invitations)").all();
  const hasEventType = columns.some((col) => col.name === "event_type");
  if (!hasEventType) {
    db.exec("ALTER TABLE invitations ADD COLUMN event_type TEXT NOT NULL DEFAULT 'mariage'");
  }
}

ensureInvitationEventTypeColumn();

app.set("view engine", "ejs");
app.set("views", path.join(ROOT, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "invitation-secret-dev",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

function loadGoogleCredentialsFromFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    const source = parsed.web || parsed.installed;
    if (!source) return null;
    return {
      clientId: String(source.client_id || "").trim(),
      clientSecret: String(source.client_secret || "").trim(),
      callbackUrl: String((source.redirect_uris && source.redirect_uris[0]) || "").trim()
    };
  } catch {
    return null;
  }
}

const googleFileCreds = loadGoogleCredentialsFromFile(GOOGLE_CREDENTIALS_PATH);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || googleFileCreds?.clientId || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || googleFileCreds?.clientSecret || "";
const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  googleFileCreds?.callbackUrl ||
  "http://localhost:3000/auth/google/callback";
const GOOGLE_OAUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

function loadWhatsAppConfigFromFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return {
      accessToken: String(parsed.access_token || "").trim(),
      phoneNumberId: String(parsed.phone_number_id || "").trim(),
      apiVersion: String(parsed.api_version || "").trim(),
      templateName: String(parsed.template_name || "").trim(),
      templateLanguage: String(parsed.template_language || "").trim(),
      templateFallbackName: String(parsed.template_fallback_name || "").trim(),
      templateFallbackLanguage: String(parsed.template_fallback_language || "").trim(),
      templateParamMode: String(parsed.template_param_mode || "").trim(),
      envelopeImageMode: String(parsed.envelope_image_mode || "").trim(),
      envelopeImageUrl: String(parsed.envelope_image_url || "").trim(),
      envelopeImageCaption: String(parsed.envelope_image_caption || "").trim()
    };
  } catch {
    return null;
  }
}

const whatsappFileConfig = loadWhatsAppConfigFromFile(WHATSAPP_CONFIG_PATH);
const WHATSAPP_ACCESS_TOKEN =
  process.env.WHATSAPP_ACCESS_TOKEN || whatsappFileConfig?.accessToken || "";
const WHATSAPP_PHONE_NUMBER_ID =
  process.env.WHATSAPP_PHONE_NUMBER_ID || whatsappFileConfig?.phoneNumberId || "";
const WHATSAPP_API_VERSION =
  process.env.WHATSAPP_API_VERSION || whatsappFileConfig?.apiVersion || "v22.0";
const WHATSAPP_TEMPLATE_NAME =
  process.env.WHATSAPP_TEMPLATE_NAME || whatsappFileConfig?.templateName || "hello_world";
const WHATSAPP_TEMPLATE_LANGUAGE =
  process.env.WHATSAPP_TEMPLATE_LANGUAGE || whatsappFileConfig?.templateLanguage || "en_US";
const WHATSAPP_TEMPLATE_FALLBACK_NAME =
  process.env.WHATSAPP_TEMPLATE_FALLBACK_NAME || whatsappFileConfig?.templateFallbackName || "hello_world";
const WHATSAPP_TEMPLATE_FALLBACK_LANGUAGE =
  process.env.WHATSAPP_TEMPLATE_FALLBACK_LANGUAGE ||
  whatsappFileConfig?.templateFallbackLanguage ||
  "en_US";
const WHATSAPP_TEMPLATE_PARAM_MODE =
  process.env.WHATSAPP_TEMPLATE_PARAM_MODE || whatsappFileConfig?.templateParamMode || "none";
const WHATSAPP_ENVELOPE_IMAGE_MODE =
  process.env.WHATSAPP_ENVELOPE_IMAGE_MODE || whatsappFileConfig?.envelopeImageMode || "none";
const WHATSAPP_ENVELOPE_IMAGE_URL =
  process.env.WHATSAPP_ENVELOPE_IMAGE_URL || whatsappFileConfig?.envelopeImageUrl || "";
const WHATSAPP_ENVELOPE_IMAGE_CAPTION =
  process.env.WHATSAPP_ENVELOPE_IMAGE_CAPTION ||
  whatsappFileConfig?.envelopeImageCaption ||
  "Ouvrir l'invitation avec le lien RSVP.";
const WHATSAPP_AUTO_ENABLED = Boolean(WHATSAPP_ACCESS_TOKEN && WHATSAPP_PHONE_NUMBER_ID);

const EVENT_TYPES = [
  { value: "mariage", label: "Mariage", invitePhrase: "vous invitent a leur mariage" },
  { value: "conference", label: "Conference", invitePhrase: "vous invitent a leur conference" },
  { value: "concert", label: "Concert", invitePhrase: "vous invitent a leur concert" },
  { value: "campagne", label: "Campagne", invitePhrase: "vous invitent a leur campagne" },
  { value: "anniversaire", label: "Anniversaire", invitePhrase: "vous invitent a leur anniversaire" },
  { value: "seminaire", label: "Seminaire", invitePhrase: "vous invitent a leur seminaire" },
  { value: "ceremonie", label: "Ceremonie", invitePhrase: "vous invitent a leur ceremonie" },
  { value: "autre", label: "Autre", invitePhrase: "vous invitent a leur evenement" }
];

function sanitizeEventType(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return EVENT_TYPES.some((item) => item.value === normalized) ? normalized : "mariage";
}

function getEventTypeMeta(value) {
  const eventType = sanitizeEventType(value);
  return EVENT_TYPES.find((item) => item.value === eventType) || EVENT_TYPES[0];
}

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = db.prepare("SELECT id, full_name, email FROM users WHERE id = ?").get(id);
  done(null, user || false);
});

if (GOOGLE_OAUTH_ENABLED) {
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
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}-${randomToken(8)}${ext}`);
  }
});

const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    cb(null, allowed.includes(file.mimetype));
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function normalizePhone(raw) {
  return String(raw || "").replace(/\D/g, "");
}

function extractPhoneFromText(raw) {
  const text = String(raw || "");
  const match = text.match(/(?:\+?\d[\d\s().-]{6,}\d)/);
  if (!match) return null;
  const normalized = normalizePhone(match[0]);
  if (normalized.length < 8) return null;
  return {
    phone: normalized,
    strippedText: text.replace(match[0], " ").replace(/\s+/g, " ").trim()
  };
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const testHash = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(testHash, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function baseUrl(req) {
  if (process.env.APP_BASE_URL) return process.env.APP_BASE_URL.replace(/\/$/, "");
  return `${req.protocol}://${req.get("host")}`;
}

function appendWhatsAppLogLine(line) {
  try {
    fs.appendFileSync(WHATSAPP_LOG_PATH, `${line}\n`, "utf8");
  } catch (error) {
    console.error("[whatsapp-log] append failed:", error?.message || error);
  }
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/connexion");
  return next();
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

app.post("/inscription", (req, res) => {
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

app.post("/connexion", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.redirect("/connexion?error=Email+ou+mot+de+passe+incorrect.");
  }

  req.session.userId = user.id;
  return res.redirect("/tableau-de-bord");
});

app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_OAUTH_ENABLED) {
    return res.redirect("/connexion?error=Connexion+Google+non+configuree+sur+le+serveur.");
  }
  return passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" })(
    req,
    res,
    next
  );
});

app.get("/auth/google/callback", (req, res, next) => {
  if (!GOOGLE_OAUTH_ENABLED) {
    return res.redirect("/connexion?error=Connexion+Google+non+configuree+sur+le+serveur.");
  }
  return passport.authenticate("google", { failureRedirect: "/connexion?error=Connexion+Google+echouee." })(
    req,
    res,
    () => {
      req.session.userId = req.user.id;
      return res.redirect("/tableau-de-bord");
    }
  );
});

app.post("/deconnexion", (req, res) => {
  req.session.destroy(() => res.redirect("/accueil.html"));
});

function parseGuests(rawText) {
  return String(rawText || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      let fullName = line;
      let phone = null;

      if (line.includes("|")) {
        const [namePart, phonePart = ""] = line.split("|");
        fullName = String(namePart || "").trim();
        const normalized = normalizePhone(phonePart);
        phone = normalized.length >= 8 ? normalized : null;
      } else {
        const extracted = extractPhoneFromText(line);
        if (extracted) {
          fullName = extracted.strippedText;
          phone = extracted.phone;
        }
      }

      fullName = String(fullName || "").replace(/[-,;]+$/, "").trim();
      if (!fullName) return null;
      return { fullName, phone };
    })
    .filter(Boolean);
}

function repairGuestsPhoneData() {
  const rows = db
    .prepare("SELECT id, full_name, phone FROM guests WHERE phone IS NULL OR TRIM(phone) = ''")
    .all();
  const updateStmt = db.prepare("UPDATE guests SET full_name = ?, phone = ? WHERE id = ?");

  for (const row of rows) {
    const extracted = extractPhoneFromText(row.full_name);
    if (!extracted || !extracted.phone || !extracted.strippedText) continue;
    updateStmt.run(extracted.strippedText, extracted.phone, row.id);
  }
}

repairGuestsPhoneData();

async function sendWhatsAppTextMessage(to, bodyText) {
  if (!WHATSAPP_AUTO_ENABLED) return { ok: false, reason: "not_configured" };
  const endpoint = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "text",
        text: {
          preview_url: true,
          body: bodyText
        }
      })
    });

    if (!response.ok) {
      let reason = `HTTP ${response.status}`;
      let metaCode = null;
      let metaSubcode = null;
      let metaMessage = "";
      try {
        const payload = await response.json();
        metaMessage = payload?.error?.message || "";
        metaCode = payload?.error?.code || null;
        metaSubcode = payload?.error?.error_subcode || null;
        reason = `HTTP ${response.status}${metaCode ? ` code ${metaCode}` : ""}${
          metaSubcode ? `/${metaSubcode}` : ""
        }${metaMessage ? `: ${metaMessage}` : ""}`;
      } catch {
        const detail = await response.text();
        if (detail) reason = `${reason}: ${detail}`;
      }
      return { ok: false, reason, metaCode, metaSubcode, metaMessage };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: String(error?.message || error), metaCode: null, metaSubcode: null };
  }
}

async function sendWhatsAppTemplateMessage(to, templateName, languageCode, bodyParams = [], options = {}) {
  if (!WHATSAPP_AUTO_ENABLED) return { ok: false, reason: "not_configured" };
  const endpoint = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;

  const components = [];
  const headerImageLink = String(options.headerImageLink || "").trim();

  if (headerImageLink) {
    components.push({
      type: "header",
      parameters: [
        {
          type: "image",
          image: { link: headerImageLink }
        }
      ]
    });
  }

  if (bodyParams.length > 0) {
    components.push({
      type: "body",
      parameters: bodyParams.map((value) => ({ type: "text", text: String(value) }))
    });
  }

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "template",
        template: {
          name: templateName,
          language: { code: languageCode },
          ...(components.length ? { components } : {})
        }
      })
    });

    if (!response.ok) {
      let reason = `HTTP ${response.status}`;
      let metaCode = null;
      let metaSubcode = null;
      let metaMessage = "";
      try {
        const payload = await response.json();
        metaMessage = payload?.error?.message || "";
        metaCode = payload?.error?.code || null;
        metaSubcode = payload?.error?.error_subcode || null;
        reason = `HTTP ${response.status}${metaCode ? ` code ${metaCode}` : ""}${
          metaSubcode ? `/${metaSubcode}` : ""
        }${metaMessage ? `: ${metaMessage}` : ""}`;
      } catch {
        const detail = await response.text();
        if (detail) reason = `${reason}: ${detail}`;
      }
      return { ok: false, reason, metaCode, metaSubcode, metaMessage };
    }

    const payload = await response.json();
    return { ok: true, payload };
  } catch (error) {
    return { ok: false, reason: String(error?.message || error), metaCode: null, metaSubcode: null };
  }
}

async function sendWhatsAppImageMessage(to, imageUrl, caption = "") {
  if (!WHATSAPP_AUTO_ENABLED) return { ok: false, reason: "not_configured" };
  const endpoint = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "image",
        image: {
          link: imageUrl,
          ...(caption ? { caption } : {})
        }
      })
    });

    if (!response.ok) {
      const payload = await response.text();
      return { ok: false, reason: `HTTP ${response.status}: ${payload}` };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: String(error?.message || error) };
  }
}

function isPublicHttpsUrl(value) {
  try {
    const parsed = new URL(String(value || ""));
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    return !["localhost", "127.0.0.1", "::1"].includes(host);
  } catch {
    return false;
  }
}

function buildEnvelopeMessage({ guestName, coupleNames, eventType, eventDate, venue, rsvpUrl }) {
  const typeMeta = getEventTypeMeta(eventType);
  return [
    `Bonjour ${guestName},`,
    "",
    `${coupleNames} ${typeMeta.invitePhrase}.`,
    `Date: ${eventDate}`,
    `Lieu: ${venue}`,
    "",
    "Ouvrez l'enveloppe et confirmez votre presence ici:",
    rsvpUrl
  ].join("\n");
}

function getDashboardInvitations(userId) {
  const rows = db
    .prepare(`
      SELECT
        i.id,
        i.event_type,
        i.couple_names,
        i.event_date,
        i.venue,
        i.created_at,
        COUNT(g.id) AS guest_count,
        SUM(CASE WHEN g.rsvp_status = 'yes' THEN 1 ELSE 0 END) AS yes_count,
        SUM(CASE WHEN g.rsvp_status = 'no' THEN 1 ELSE 0 END) AS no_count
      FROM invitations i
      LEFT JOIN guests g ON g.invitation_id = i.id
      WHERE i.owner_user_id = ?
      GROUP BY i.id
      ORDER BY i.created_at DESC
    `)
    .all(userId);

  return rows;
}

app.get("/tableau-de-bord", requireAuth, (req, res) => {
  return res.render("dashboard", {
    invitations: getDashboardInvitations(req.session.userId),
    eventTypes: EVENT_TYPES,
    success: req.query.success || "",
    error: req.query.error || ""
  });
});

app.post("/tableau-de-bord/invitation/:id/supprimer", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT id FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);

  if (!invitation) {
    return res
      .status(404)
      .redirect("/tableau-de-bord?error=Invitation+introuvable+ou+acces+refuse.");
  }

  db.prepare("DELETE FROM invitations WHERE id = ?").run(invitation.id);
  return res.redirect("/tableau-de-bord?success=Invitation+supprimee+avec+succes.");
});

app.post("/tableau-de-bord/historique/supprimer", requireAuth, (req, res) => {
  db.prepare("DELETE FROM invitations WHERE owner_user_id = ?").run(req.session.userId);
  return res.redirect("/tableau-de-bord?success=Historique+des+invitations+supprime.");
});

app.get("/tableau-de-bord/nouvelle-invitation", requireAuth, (_req, res) => {
  return res.render("invitation-form", {
    invitation: null,
    action: "/tableau-de-bord/nouvelle-invitation",
    error: "",
    eventTypes: EVENT_TYPES,
    selectedEventType: ""
  });
});

app.post("/tableau-de-bord/nouvelle-invitation", requireAuth, upload.single("image"), async (req, res) => {
  const rawEventType = String(req.body.eventType || "").trim().toLowerCase();
  const eventTypeIsValid = EVENT_TYPES.some((item) => item.value === rawEventType);
  const eventType = eventTypeIsValid ? rawEventType : "mariage";
  const coupleNames = String(req.body.coupleNames || "").trim();
  const eventDate = String(req.body.eventDate || "").trim();
  const venue = String(req.body.venue || "").trim();
  const message = String(req.body.message || "").trim();
  const ogTitle = String(req.body.ogTitle || "").trim();
  const ogDescription = String(req.body.ogDescription || "").trim();

  if (!eventTypeIsValid || !coupleNames || !eventDate || !venue || !message) {
    return res.render("invitation-form", {
      invitation: null,
      action: "/tableau-de-bord/nouvelle-invitation",
      error: "Tous les champs principaux sont obligatoires, y compris le type d'invitation.",
      eventTypes: EVENT_TYPES,
      selectedEventType: eventTypeIsValid ? eventType : ""
    });
  }

  const invitationId = randomToken(10);
  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
  const guests = parseGuests(req.body.guests || "");

  const createdGuests = [];
  const tx = db.transaction(() => {
    db.prepare(
      `INSERT INTO invitations
       (id, owner_user_id, event_type, couple_names, event_date, venue, message, image_path, og_title, og_description)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      invitationId,
      req.session.userId,
      eventType,
      coupleNames,
      eventDate,
      venue,
      message,
      imagePath,
      ogTitle || null,
      ogDescription || null
    );

    const guestStmt = db.prepare(
      "INSERT INTO guests (invitation_id, full_name, phone, token) VALUES (?, ?, ?, ?)"
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
  const failedMetaCodes = [];
  let imageSkippedCount = 0;
  const dispatchReports = [];
  const dispatchStartedAt = new Date().toISOString();

  for (const guest of createdGuests) {
    if (!guest.phone) {
      skippedCount += 1;
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
    } else {
      failedCount += 1;
      if (result.reason) failedReasons.push(result.reason);
      if (result.metaCode) failedMetaCodes.push(result.metaCode);
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
    if (failedMetaCodes.includes(133010)) {
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
         SUM(CASE WHEN rsvp_status = 'no' THEN 1 ELSE 0 END) AS no_count
       FROM guests WHERE invitation_id = ?`
    )
    .get(invitation.id);

  return res.render("invitation-manage", {
    invitation,
    guests,
    stats,
    eventTypes: EVENT_TYPES,
    selectedEventType: sanitizeEventType(invitation.event_type),
    success: req.query.success || "",
    error: req.query.error || ""
  });
});

app.post(
  "/tableau-de-bord/invitation/:id/modifier",
  requireAuth,
  upload.single("image"),
  (req, res) => {
    const invitation = db
      .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
      .get(req.params.id, req.session.userId);
    if (!invitation) return res.status(404).render("not-found");

    const eventType = sanitizeEventType(req.body.eventType || invitation.event_type);
    const coupleNames = String(req.body.coupleNames || "").trim();
    const eventDate = String(req.body.eventDate || "").trim();
    const venue = String(req.body.venue || "").trim();
    const message = String(req.body.message || "").trim();
    const ogTitle = String(req.body.ogTitle || "").trim();
    const ogDescription = String(req.body.ogDescription || "").trim();

    if (!coupleNames || !eventDate || !venue || !message) {
      return res.redirect(
        `/tableau-de-bord/invitation/${invitation.id}?error=Tous+les+champs+principaux+sont+obligatoires.`
      );
    }

    const imagePath = req.file ? `/uploads/${req.file.filename}` : invitation.image_path;
    db.prepare(
      `UPDATE invitations
       SET event_type = ?, couple_names = ?, event_date = ?, venue = ?, message = ?, image_path = ?, og_title = ?, og_description = ?
       WHERE id = ?`
    ).run(
      eventType,
      coupleNames,
      eventDate,
      venue,
      message,
      imagePath,
      ogTitle || null,
      ogDescription || null,
      invitation.id
    );

    const guests = parseGuests(req.body.newGuests || "");
    if (guests.length) {
      const tx = db.transaction(() => {
        const guestStmt = db.prepare(
          "INSERT INTO guests (invitation_id, full_name, phone, token) VALUES (?, ?, ?, ?)"
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
});

app.get("/tableau-de-bord/invitation/:id/pdf", requireAuth, (req, res) => {
  const invitation = db
    .prepare("SELECT * FROM invitations WHERE id = ? AND owner_user_id = ?")
    .get(req.params.id, req.session.userId);
  if (!invitation) return res.status(404).render("not-found");

  const guests = db
    .prepare("SELECT * FROM guests WHERE invitation_id = ? ORDER BY full_name")
    .all(invitation.id);

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
  doc.moveDown();
  guests.forEach((guest, index) => {
    const status =
      guest.rsvp_status === "yes" ? "Present" : guest.rsvp_status === "no" ? "Absent" : "En attente";
    doc.text(`${index + 1}. ${guest.full_name} | ${guest.phone || "Sans numero"} | ${status}`);
  });
  doc.end();
});

app.get("/rsvp/:token", (req, res) => {
  const data = db
    .prepare(
      `SELECT
         g.id AS guest_id,
         g.full_name,
         g.phone,
         g.rsvp_status,
         g.responded_at,
         i.id AS invitation_id,
         i.event_type,
         i.couple_names,
         i.event_date,
         i.venue,
         i.message,
         i.image_path,
         i.og_title,
         i.og_description
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

app.post("/rsvp/:token", (req, res) => {
  const status = req.body.status === "yes" ? "yes" : req.body.status === "no" ? "no" : null;
  if (!status) return res.redirect(`/rsvp/${req.params.token}`);

  const guest = db.prepare("SELECT * FROM guests WHERE token = ?").get(req.params.token);
  if (!guest) return res.status(404).render("not-found");

  const tx = db.transaction(() => {
    db.prepare("UPDATE guests SET rsvp_status = ?, responded_at = CURRENT_TIMESTAMP WHERE id = ?").run(
      status,
      guest.id
    );
    db.prepare("INSERT INTO rsvp_events (invitation_id, guest_id, status) VALUES (?, ?, ?)").run(
      guest.invitation_id,
      guest.id,
      status
    );
  });
  tx();

  return res.redirect(`/rsvp/${req.params.token}?success=Votre+reponse+a+ete+enregistree.`);
});

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

app.use((_req, res) => res.status(404).render("not-found"));

app.listen(PORT, () => {
  console.log(`Serveur actif sur http://localhost:${PORT}`);
});
