document.addEventListener("DOMContentLoaded", () => {
  const scene = document.getElementById("scene");
  const openToggle = document.getElementById("openToggle");
  const successToast = document.getElementById("successToast");
  const shouldAutoOpen = scene?.dataset?.autoOpen === "1";
  let opened = false;

  function renderEnvelopeState() {
    if (!scene || !openToggle) return;
    scene.classList.toggle("open", opened);
    openToggle.textContent = opened ? "Fermer l'invitation" : "Ouvrir l'invitation";
  }

  if (openToggle) {
    openToggle.addEventListener("click", () => {
      opened = !opened;
      renderEnvelopeState();
    });
  }

  if (scene) {
    scene.addEventListener("click", (event) => {
      if (!event.target.closest("button") && !event.target.closest("form")) {
        opened = !opened;
        renderEnvelopeState();
      }
    });
  }

  if (shouldAutoOpen) {
    opened = true;
    renderEnvelopeState();
    if (successToast) successToast.classList.add("show");
    setTimeout(() => {
      opened = false;
      renderEnvelopeState();
    }, 1100);
    setTimeout(() => {
      if (successToast) successToast.classList.remove("show");
    }, 2700);
  }

  renderEnvelopeState();
});
