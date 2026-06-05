const path = require("path");
const fs = require("fs");
const dotenv = require("dotenv");

dotenv.config();

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const VIEWS_DIR = path.join(ROOT, "views");
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, "data"));
const UPLOADS_DIR = path.resolve(process.env.UPLOADS_DIR || path.join(PUBLIC_DIR, "uploads"));
const LOGS_DIR = path.resolve(process.env.LOGS_DIR || path.join(ROOT, "logs"));
const GOOGLE_CREDENTIALS_PATH = process.env.GOOGLE_CREDENTIALS_PATH || path.join(ROOT, "google-oauth-client.json");
const WHATSAPP_CONFIG_PATH = process.env.WHATSAPP_CONFIG_PATH || path.join(ROOT, "whatsapp-config.json");

function loadJsonFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function loadGoogleCredentials(filePath) {
  const parsed = loadJsonFile(filePath);
  if (!parsed) return null;
  const source = parsed.web || parsed.installed;
  if (!source) return null;
  return {
    clientId: String(source.client_id || "").trim(),
    clientSecret: String(source.client_secret || "").trim(),
    callbackUrl: String((source.redirect_uris && source.redirect_uris[0]) || "").trim()
  };
}

function loadWhatsAppConfig(filePath) {
  const parsed = loadJsonFile(filePath);
  if (!parsed) return null;
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
}

const googleFileCreds = loadGoogleCredentials(GOOGLE_CREDENTIALS_PATH);
const whatsappFileConfig = loadWhatsAppConfig(WHATSAPP_CONFIG_PATH);

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || googleFileCreds?.clientId || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || googleFileCreds?.clientSecret || "";
const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL || googleFileCreds?.callbackUrl || "http://localhost:3000/auth/google/callback";
const GOOGLE_OAUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

const WHATSAPP_ACCESS_TOKEN =
  process.env.WHATSAPP_ACCESS_TOKEN || whatsappFileConfig?.accessToken || "";
const WHATSAPP_PHONE_NUMBER_ID =
  process.env.WHATSAPP_PHONE_NUMBER_ID || whatsappFileConfig?.phoneNumberId || "";
const WHATSAPP_API_VERSION = process.env.WHATSAPP_API_VERSION || whatsappFileConfig?.apiVersion || "v22.0";
const WHATSAPP_TEMPLATE_NAME =
  process.env.WHATSAPP_TEMPLATE_NAME || whatsappFileConfig?.templateName || "hello_world";
const WHATSAPP_TEMPLATE_LANGUAGE =
  process.env.WHATSAPP_TEMPLATE_LANGUAGE || whatsappFileConfig?.templateLanguage || "en_US";
const WHATSAPP_TEMPLATE_FALLBACK_NAME =
  process.env.WHATSAPP_TEMPLATE_FALLBACK_NAME || whatsappFileConfig?.templateFallbackName || "hello_world";
const WHATSAPP_TEMPLATE_FALLBACK_LANGUAGE =
  process.env.WHATSAPP_TEMPLATE_FALLBACK_LANGUAGE || whatsappFileConfig?.templateFallbackLanguage || "en_US";
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

const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, "");
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "invitation-secret-dev";
const NODE_ENV = process.env.NODE_ENV || "development";
const isProduction = NODE_ENV === "production";

if (isProduction && SESSION_SECRET === "invitation-secret-dev") {
  throw new Error("SESSION_SECRET doit etre defini en production.");
}

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

const INVITATION_TEMPLATES = [
  {
    value: "mariage-elegant",
    label: "Mariage elegant",
    eventType: "mariage",
    message:
      "Nous serions heureux de vous compter parmi nous pour celebrer ce moment unique. Merci de confirmer votre presence."
  },
  {
    value: "anniversaire-festif",
    label: "Anniversaire festif",
    eventType: "anniversaire",
    message:
      "Une belle fete se prepare et votre presence compte beaucoup. Confirmez votre venue pour partager ce moment avec nous."
  },
  {
    value: "conference-pro",
    label: "Conference professionnelle",
    eventType: "conference",
    message:
      "Vous etes invite a participer a notre rencontre. Merci de confirmer votre presence afin de faciliter l'organisation."
  },
  {
    value: "concert-live",
    label: "Concert live",
    eventType: "concert",
    message:
      "Rejoignez-nous pour une soiree musicale. Confirmez votre presence pour recevoir les dernieres informations pratiques."
  },
  {
    value: "ceremonie-classique",
    label: "Ceremonie classique",
    eventType: "ceremonie",
    message:
      "Votre presence honorera cette ceremonie. Merci de nous indiquer votre disponibilite via le lien RSVP."
  }
];

const THEME_ACCENTS = [
  { value: "bleu", label: "Bleu royal", color: "#0455bf" },
  { value: "rose", label: "Rose ceremonie", color: "#c43d7d" },
  { value: "vert", label: "Vert jardin", color: "#16804c" },
  { value: "or", label: "Or classique", color: "#a66a00" },
  { value: "ardoise", label: "Ardoise sobre", color: "#334155" }
];

const THEME_FONTS = [
  { value: "sans", label: "Moderne" },
  { value: "serif", label: "Elegant" },
  { value: "classic", label: "Classique" }
];

const THEME_STYLES = [
  { value: "envelope", label: "Enveloppe" },
  { value: "card", label: "Carte simple" },
  { value: "editorial", label: "Editorial" }
];

module.exports = {
  ROOT,
  PUBLIC_DIR,
  VIEWS_DIR,
  DATA_DIR,
  UPLOADS_DIR,
  LOGS_DIR,
  GOOGLE_CREDENTIALS_PATH,
  WHATSAPP_CONFIG_PATH,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL,
  GOOGLE_OAUTH_ENABLED,
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
  WHATSAPP_AUTO_ENABLED,
  APP_BASE_URL,
  PORT,
  SESSION_SECRET,
  NODE_ENV,
  isProduction,
  EVENT_TYPES,
  INVITATION_TEMPLATES,
  THEME_ACCENTS,
  THEME_FONTS,
  THEME_STYLES
};
