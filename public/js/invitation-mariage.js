document.addEventListener("DOMContentLoaded", () => {
  const scene = document.getElementById("scene");
  const openBtn = document.getElementById("openBtn");
  const toggleEditor = document.getElementById("toggleEditor");
  const closeEditor = document.getElementById("closeEditor");
  const editorPanel = document.getElementById("editorPanel");
  const resetBtn = document.getElementById("resetBtn");
  const copyMsgBtn = document.getElementById("copyMsgBtn");
  const buildWaBtn = document.getElementById("buildWaBtn");
  const waLinksBox = document.getElementById("waLinksBox");
  const waNote = document.getElementById("waNote");
  const inpRecipients = document.getElementById("inpRecipients");
  const sendTestBtn = document.getElementById("sendTestBtn");
  const inpPublicUrl = document.getElementById("inpPublicUrl");
  const sealText = document.getElementById("sealText");

  const textCard = document.getElementById("textCard");
  const imageCard = document.getElementById("imageCard");
  const posterPreview = document.getElementById("posterPreview");
  const posterPlaceholder = document.getElementById("posterPlaceholder");

  const inpNames = document.getElementById("inpNames");
  const inpDate = document.getElementById("inpDate");
  const inpLieu = document.getElementById("inpLieu");
  const inpMessage = document.getElementById("inpMessage");
  const inpImage = document.getElementById("inpImage");

  const cardNames = document.getElementById("cardNames");
  const cardDate = document.getElementById("cardDate");
  const cardLieu = document.getElementById("cardLieu");
  const cardMessage = document.getElementById("cardMessage");

  if (
    !scene ||
    !openBtn ||
    !toggleEditor ||
    !closeEditor ||
    !editorPanel ||
    !resetBtn ||
    !copyMsgBtn ||
    !buildWaBtn ||
    !waLinksBox ||
    !waNote ||
    !inpRecipients ||
    !sendTestBtn ||
    !inpPublicUrl ||
    !sealText ||
    !textCard ||
    !imageCard ||
    !posterPreview ||
    !posterPlaceholder ||
    !inpNames ||
    !inpDate ||
    !inpLieu ||
    !inpMessage ||
    !inpImage ||
    !cardNames ||
    !cardDate ||
    !cardLieu ||
    !cardMessage
  ) {
    return;
  }

  const defaults = {
    names: "Amina & Daniel",
    date: "15 Aout 2026 - 16h00",
    lieu: "Hotel Royal Palace, Lome",
    message: "Merci de confirmer votre presence avant le 30 Juillet 2026."
  };

  let opened = false;
  let mode = "text";

  function initialsFromNames(raw) {
    const parts = String(raw || "")
      .split("&")
      .join(" ")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (!parts.length) return "A&D";
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + "&" + parts[parts.length - 1][0]).toUpperCase();
  }

  function toggleEnvelope() {
    opened = !opened;
    scene.classList.toggle("open", opened);
    openBtn.textContent = opened ? "Refermer l'enveloppe" : "Ouvrir l'enveloppe";
  }

  function syncTextCard() {
    const names = inpNames.value.trim() || defaults.names;
    cardNames.textContent = names;
    sealText.textContent = initialsFromNames(names);
    cardDate.innerHTML = `📅 <strong>${inpDate.value.trim() || defaults.date}</strong>`;
    cardLieu.innerHTML = `📍 <strong>Lieu :</strong> ${inpLieu.value.trim() || defaults.lieu}`;
    cardMessage.innerHTML = `💌 ${inpMessage.value.trim() || defaults.message}`;
  }

  function buildMessageText() {
    const names = inpNames.value.trim() || defaults.names;
    const date = inpDate.value.trim() || defaults.date;
    const lieu = inpLieu.value.trim() || defaults.lieu;
    const message = inpMessage.value.trim() || defaults.message;
    const baseLink = inpPublicUrl.value.trim() || window.location.href.split("?")[0];
    const shareParams = new URLSearchParams({ names, date, lieu, msg: message });
    const link = `${baseLink}?${shareParams.toString()}`;
    return `${link}\n\n✨ ${names} ✨\n\nAvec la benediction de nos familles, nous avons la joie de vous inviter a celebrer notre union.\n\n📅 ${date}\n📍 ${lieu}\n\n💌 ${message}`;
  }

  async function copyMessageToClipboard() {
    const txt = buildMessageText();
    try {
      await navigator.clipboard.writeText(txt);
      waNote.textContent = "Message copie. Vous pouvez le coller dans WhatsApp.";
    } catch {
      waNote.textContent = "Copie automatique impossible ici. Selectionnez puis copiez manuellement.";
    }
  }

  function normalizePhone(raw) {
    const onlyDigits = String(raw).replace(/\D/g, "");
    return onlyDigits;
  }

  function buildWhatsAppLinks() {
    const lines = inpRecipients.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const message = encodeURIComponent(buildMessageText());
    waLinksBox.innerHTML = "";

    if (!lines.length) {
      waNote.textContent = "Ajoutez au moins un numero destinataire.";
      return;
    }

    const links = lines.map(normalizePhone).filter((p) => p.length >= 8);
    if (!links.length) {
      waNote.textContent = "Format invalide. Exemple: 22890000000";
      return;
    }

    links.forEach((phone, idx) => {
      const a = document.createElement("a");
      a.href = `https://wa.me/${phone}?text=${message}`;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = `Ouvrir WhatsApp destinataire ${idx + 1} (${phone})`;
      waLinksBox.appendChild(a);
    });

    waNote.textContent =
      "Pour voir l'enveloppe en apercu dans WhatsApp, utilisez une URL publique HTTPS avec balises Open Graph (og:title, og:description, og:image).";
  }

  function sendWhatsAppTest() {
    const firstLine = inpRecipients.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .find(Boolean);
    if (!firstLine) {
      waNote.textContent = "Ajoutez d'abord votre numero dans Destinataires (ex: 22890000000).";
      return;
    }
    const phone = normalizePhone(firstLine);
    if (phone.length < 8) {
      waNote.textContent = "Numero invalide. Exemple: 22890000000";
      return;
    }
    const message = encodeURIComponent(buildMessageText());
    window.open(`https://wa.me/${phone}?text=${message}`, "_blank", "noopener");
  }

  function setMode(nextMode) {
    mode = nextMode;
    const isImage = mode === "image";
    textCard.classList.toggle("hidden", isImage);
    imageCard.classList.toggle("hidden", !isImage);
  }

  function resetAll() {
    inpNames.value = defaults.names;
    inpDate.value = defaults.date;
    inpLieu.value = defaults.lieu;
    inpMessage.value = defaults.message;
    inpImage.value = "";
    inpRecipients.value = "";
    inpPublicUrl.value = "";
    posterPreview.removeAttribute("src");
    posterPreview.classList.add("hidden");
    posterPlaceholder.classList.remove("hidden");
    waLinksBox.innerHTML = "";
    waNote.textContent = "";
    document.querySelector('input[name="displayMode"][value="text"]').checked = true;
    setMode("text");
    syncTextCard();
  }

  openBtn.addEventListener("click", toggleEnvelope);
  toggleEditor.addEventListener("click", () => editorPanel.classList.toggle("open"));
  closeEditor.addEventListener("click", () => editorPanel.classList.remove("open"));
  resetBtn.addEventListener("click", resetAll);
  copyMsgBtn.addEventListener("click", copyMessageToClipboard);
  buildWaBtn.addEventListener("click", buildWhatsAppLinks);
  sendTestBtn.addEventListener("click", sendWhatsAppTest);

  [inpNames, inpDate, inpLieu, inpMessage].forEach((el) => {
    el.addEventListener("input", syncTextCard);
  });

  document.querySelectorAll('input[name="displayMode"]').forEach((radio) => {
    radio.addEventListener("change", () => setMode(radio.value));
  });

  inpImage.addEventListener("change", () => {
    const file = inpImage.files && inpImage.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      posterPreview.src = String(reader.result);
      posterPreview.classList.remove("hidden");
      posterPlaceholder.classList.add("hidden");
      document.querySelector('input[name="displayMode"][value="image"]').checked = true;
      setMode("image");
    };
    reader.readAsDataURL(file);
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".editor") && !event.target.closest("#toggleEditor")) {
      editorPanel.classList.remove("open");
    }
  });

  const qs = new URLSearchParams(window.location.search);
  if (qs.get("names")) inpNames.value = qs.get("names");
  if (qs.get("date")) inpDate.value = qs.get("date");
  if (qs.get("lieu")) inpLieu.value = qs.get("lieu");
  if (qs.get("msg")) inpMessage.value = qs.get("msg");
  if (window.location.protocol === "file:") {
    waNote.textContent =
      "Apercu WhatsApp non disponible en local (file://). Hebergez la page en HTTPS pour afficher l'enveloppe dans la messagerie du destinataire.";
  }
  syncTextCard();
});
