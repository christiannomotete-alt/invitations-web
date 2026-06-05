const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const { DATA_DIR, ROOT } = require("./config");

const DB_PATH = path.join(DATA_DIR, "invitation.db");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");

function ensureUsersGoogleColumn() {
  const columns = db.prepare("PRAGMA table_info(users)").all();
  const hasGoogleId = columns.some((col) => col.name === "google_id");
  if (!hasGoogleId) {
    db.exec("ALTER TABLE users ADD COLUMN google_id TEXT");
  }
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL");
}

function ensureInvitationEventTypeColumn() {
  const columns = db.prepare("PRAGMA table_info(invitations)").all();
  const hasEventType = columns.some((col) => col.name === "event_type");
  if (!hasEventType) {
    db.exec("ALTER TABLE invitations ADD COLUMN event_type TEXT NOT NULL DEFAULT 'mariage'");
  }
}

function ensureInvitationEventDateIsoColumn() {
  const columns = db.prepare("PRAGMA table_info(invitations)").all();
  const hasEventDateIso = columns.some((col) => col.name === "event_date_iso");
  if (!hasEventDateIso) {
    db.exec("ALTER TABLE invitations ADD COLUMN event_date_iso TEXT");
  }
}

function ensureInvitationPlanningColumns() {
  const columns = db.prepare("PRAGMA table_info(invitations)").all();
  const hasTemplateKey = columns.some((col) => col.name === "template_key");
  const hasCapacity = columns.some((col) => col.name === "capacity");
  const hasOrganizerPhone = columns.some((col) => col.name === "organizer_phone");
  const hasSchedule = columns.some((col) => col.name === "schedule");
  const hasDressCode = columns.some((col) => col.name === "dress_code");
  const hasMapUrl = columns.some((col) => col.name === "map_url");
  const hasThemeAccent = columns.some((col) => col.name === "theme_accent");
  const hasThemeFont = columns.some((col) => col.name === "theme_font");
  const hasThemeStyle = columns.some((col) => col.name === "theme_style");

  if (!hasTemplateKey) db.exec("ALTER TABLE invitations ADD COLUMN template_key TEXT");
  if (!hasCapacity) db.exec("ALTER TABLE invitations ADD COLUMN capacity INTEGER");
  if (!hasOrganizerPhone) db.exec("ALTER TABLE invitations ADD COLUMN organizer_phone TEXT");
  if (!hasSchedule) db.exec("ALTER TABLE invitations ADD COLUMN schedule TEXT");
  if (!hasDressCode) db.exec("ALTER TABLE invitations ADD COLUMN dress_code TEXT");
  if (!hasMapUrl) db.exec("ALTER TABLE invitations ADD COLUMN map_url TEXT");
  if (!hasThemeAccent) db.exec("ALTER TABLE invitations ADD COLUMN theme_accent TEXT");
  if (!hasThemeFont) db.exec("ALTER TABLE invitations ADD COLUMN theme_font TEXT");
  if (!hasThemeStyle) db.exec("ALTER TABLE invitations ADD COLUMN theme_style TEXT");
}

function ensureGuestRsvpDetailColumns() {
  const columns = db.prepare("PRAGMA table_info(guests)").all();
  const hasPlusOne = columns.some((col) => col.name === "plus_one");
  const hasAttendeeCount = columns.some((col) => col.name === "attendee_count");
  const hasMenuChoice = columns.some((col) => col.name === "menu_choice");
  const hasAllergies = columns.some((col) => col.name === "allergies");
  const hasComment = columns.some((col) => col.name === "comment");

  if (!hasPlusOne) db.exec("ALTER TABLE guests ADD COLUMN plus_one INTEGER NOT NULL DEFAULT 0");
  if (!hasAttendeeCount) db.exec("ALTER TABLE guests ADD COLUMN attendee_count INTEGER NOT NULL DEFAULT 1");
  if (!hasMenuChoice) db.exec("ALTER TABLE guests ADD COLUMN menu_choice TEXT");
  if (!hasAllergies) db.exec("ALTER TABLE guests ADD COLUMN allergies TEXT");
  if (!hasComment) db.exec("ALTER TABLE guests ADD COLUMN comment TEXT");
}

function ensureGuestOperationsColumns() {
  const columns = db.prepare("PRAGMA table_info(guests)").all();
  const hasCategory = columns.some((col) => col.name === "category");
  const hasTableName = columns.some((col) => col.name === "table_name");
  const hasSeatLabel = columns.some((col) => col.name === "seat_label");
  const hasMaxPlusOnes = columns.some((col) => col.name === "max_plus_ones");
  const hasWhatsappStatus = columns.some((col) => col.name === "whatsapp_status");
  const hasWhatsappDetail = columns.some((col) => col.name === "whatsapp_detail");
  const hasWhatsappSentAt = columns.some((col) => col.name === "whatsapp_sent_at");
  const hasLastReminderAt = columns.some((col) => col.name === "last_reminder_at");
  const hasCheckedInAt = columns.some((col) => col.name === "checked_in_at");

  if (!hasCategory) db.exec("ALTER TABLE guests ADD COLUMN category TEXT");
  if (!hasTableName) db.exec("ALTER TABLE guests ADD COLUMN table_name TEXT");
  if (!hasSeatLabel) db.exec("ALTER TABLE guests ADD COLUMN seat_label TEXT");
  if (!hasMaxPlusOnes) db.exec("ALTER TABLE guests ADD COLUMN max_plus_ones INTEGER NOT NULL DEFAULT 1");
  if (!hasWhatsappStatus) db.exec("ALTER TABLE guests ADD COLUMN whatsapp_status TEXT NOT NULL DEFAULT 'not_sent'");
  if (!hasWhatsappDetail) db.exec("ALTER TABLE guests ADD COLUMN whatsapp_detail TEXT");
  if (!hasWhatsappSentAt) db.exec("ALTER TABLE guests ADD COLUMN whatsapp_sent_at TEXT");
  if (!hasLastReminderAt) db.exec("ALTER TABLE guests ADD COLUMN last_reminder_at TEXT");
  if (!hasCheckedInAt) db.exec("ALTER TABLE guests ADD COLUMN checked_in_at TEXT");
}

function initSchema() {
  db.exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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
  event_date_iso TEXT,
  venue TEXT NOT NULL,
  message TEXT NOT NULL,
  image_path TEXT,
  og_title TEXT,
  og_description TEXT,
  template_key TEXT,
  capacity INTEGER,
  organizer_phone TEXT,
  schedule TEXT,
  dress_code TEXT,
  map_url TEXT,
  theme_accent TEXT,
  theme_font TEXT,
  theme_style TEXT,
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
  plus_one INTEGER NOT NULL DEFAULT 0,
  attendee_count INTEGER NOT NULL DEFAULT 1,
  menu_choice TEXT,
  allergies TEXT,
  comment TEXT,
  category TEXT,
  table_name TEXT,
  seat_label TEXT,
  max_plus_ones INTEGER NOT NULL DEFAULT 1,
  whatsapp_status TEXT NOT NULL DEFAULT 'not_sent',
  whatsapp_detail TEXT,
  whatsapp_sent_at TEXT,
  last_reminder_at TEXT,
  checked_in_at TEXT,
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

CREATE TABLE IF NOT EXISTS reminder_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id TEXT NOT NULL,
  guest_id INTEGER NOT NULL,
  reminder_key TEXT NOT NULL,
  whatsapp_status TEXT NOT NULL DEFAULT 'pending' CHECK (whatsapp_status IN ('pending', 'sent', 'failed')),
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(guest_id, reminder_key),
  FOREIGN KEY(invitation_id) REFERENCES invitations(id) ON DELETE CASCADE,
  FOREIGN KEY(guest_id) REFERENCES guests(id) ON DELETE CASCADE
);
  `);
  ensureUsersGoogleColumn();
  ensureInvitationEventTypeColumn();
  ensureInvitationEventDateIsoColumn();
  ensureInvitationPlanningColumns();
  ensureGuestRsvpDetailColumns();
  ensureGuestOperationsColumns();
  db.prepare("INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)").run("2026-06-04-operations-fields");
  db.prepare("INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)").run("2026-06-05-visual-fields");
}

function repairGuestsPhoneData(dbInstance, extractPhoneFromText) {
  const rows = db.prepare("SELECT id, full_name, phone FROM guests WHERE phone IS NULL OR TRIM(phone) = ''").all();
  const updateStmt = db.prepare("UPDATE guests SET full_name = ?, phone = ? WHERE id = ?");

  for (const row of rows) {
    const extracted = extractPhoneFromText(row.full_name);
    if (!extracted || !extracted.phone || !extracted.strippedText) continue;
    updateStmt.run(extracted.strippedText, extracted.phone, row.id);
  }
}

module.exports = {
  db,
  initSchema,
  repairGuestsPhoneData
};
