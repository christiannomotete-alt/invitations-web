const {
  WHATSAPP_AUTO_ENABLED,
  WHATSAPP_API_VERSION,
  WHATSAPP_PHONE_NUMBER_ID,
  WHATSAPP_ACCESS_TOKEN
} = require("./config");

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
        reason = `HTTP ${response.status}${metaCode ? ` code ${metaCode}` : ``}${
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
        reason = `HTTP ${response.status}${metaCode ? ` code ${metaCode}` : ``}${
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

module.exports = {
  sendWhatsAppTextMessage,
  sendWhatsAppTemplateMessage,
  sendWhatsAppImageMessage
};
