const { EVENT_TYPES } = require("./config");
const crypto = require("crypto");

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

function sanitizeEventType(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return EVENT_TYPES.some((item) => item.value === normalized) ? normalized : "mariage";
}

function getEventTypeMeta(value) {
  const eventType = sanitizeEventType(value);
  return EVENT_TYPES.find((item) => item.value === eventType) || EVENT_TYPES[0];
}

const { APP_BASE_URL } = require("./config");

function baseUrl(req) {
  if (APP_BASE_URL) return APP_BASE_URL.replace(/\/$/, "");
  return `${req.protocol}://${req.get("host")}`;
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

module.exports = {
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
  parseGuests
};
