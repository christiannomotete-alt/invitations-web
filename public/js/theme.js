(() => {
  const root = document.documentElement;
  const button = document.getElementById("themeToggle");
  const profileToggle = document.getElementById("profileToggle");
  const profileDropdown = document.getElementById("profileDropdown");
  const showPasswordOption = document.getElementById("showPasswordOption");

  function currentTheme() {
    return root.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }

  if (!root.getAttribute("data-theme")) {
    applyTheme("light");
  }

  if (button) {
    button.addEventListener("click", () => {
      applyTheme(currentTheme() === "dark" ? "light" : "dark");
    });
  }

  if (profileToggle && profileDropdown) {
    profileToggle.addEventListener("click", (event) => {
      event.stopPropagation();
      profileDropdown.classList.toggle("open");
    });

    document.addEventListener("click", (event) => {
      if (!event.target.closest("#profileMenu")) {
        profileDropdown.classList.remove("open");
      }
    });
  }

  if (showPasswordOption) {
    showPasswordOption.addEventListener("click", () => {
      window.alert(
        "Pour des raisons de securite, votre mot de passe n'est pas affichable. Vous pouvez en definir un nouveau depuis la page de connexion si besoin."
      );
    });
  }

  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      alert.style.transition = "opacity 0.35s ease, transform 0.35s ease";
      alert.style.opacity = "0";
      alert.style.transform = "translateY(-6px)";
      setTimeout(() => {
        if (alert.parentNode) alert.parentNode.removeChild(alert);
      }, 380);
    }, 3200);
  });
})();
