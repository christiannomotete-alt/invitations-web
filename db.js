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

function initSchema() {
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
  event_date_iso TEXT,
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
  plus_one INTEGER NOT NULL DEFAULT 0,
  attendee_count INTEGER NOT NULL DEFAULT 1,
  menu_choice TEXT,
  allergies TEXT,
  comment TEXT,
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
  ensureGuestRsvpDetailColumns();
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
