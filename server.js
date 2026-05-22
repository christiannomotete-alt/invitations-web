const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const multer = require("multer");
const PDFDocument = require("pdfkit");

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
  parseGuests
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
  EVENT_TYPES,
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

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/connexion");
  return next();
}

function getDashboardInvitations(userId) {
  return db
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

const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    cb(null, allowed.includes(file.mimetype));
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

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
