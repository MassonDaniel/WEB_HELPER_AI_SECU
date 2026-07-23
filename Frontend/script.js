// URL de l'API backend. Modifie cette valeur si ton backend tourne ailleurs.
const API_URL = "http://localhost:3000";

const scanForm = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const formError = document.getElementById("form-error");

const loadingState = document.getElementById("loading-state");
const loadingText = document.getElementById("loading-text");
const resultsSection = document.getElementById("results");
const errorState = document.getElementById("error-state");
const errorMessage = document.getElementById("error-message");

const scoreValue = document.getElementById("score-value");
const scoreGrade = document.getElementById("score-grade");
const scoreUrl = document.getElementById("score-url");
const scoreSummary = document.getElementById("score-summary");
const dialFill = document.getElementById("dial-fill");
const categoriesContainer = document.getElementById("categories");

const reportBtn = document.getElementById("report-btn");
const reportBody = document.getElementById("report-body");

const CATEGORY_LABELS = {
  headers: "En-têtes de sécurité",
  cookies: "Cookies",
  files: "Fichiers sensibles exposés",
  technologies: "Technologies détectées",
};

const GRADE_COLORS = {
  A: "#1F5C4D",
  B: "#1F5C4D",
  C: "#9A6300",
  D: "#9C2B2B",
  F: "#9C2B2B",
};

const LOADING_MESSAGES = [
  "Connexion à la cible…",
  "Lecture des en-têtes de réponse…",
  "Vérification des cookies…",
  "Recherche de fichiers exposés…",
  "Identification des technologies…",
];

let lastAuditJson = null;
let loadingInterval = null;

// ---------- Helpers ----------

function resetSections() {
  loadingState.hidden = true;
  resultsSection.hidden = true;
  errorState.hidden = true;
  formError.hidden = true;
}

function showLoading() {
  resetSections();
  loadingState.hidden = false;
  let i = 0;
  loadingText.textContent = LOADING_MESSAGES[0];
  loadingInterval = setInterval(() => {
    i = (i + 1) % LOADING_MESSAGES.length;
    loadingText.textContent = LOADING_MESSAGES[i];
  }, 1800);
}

function stopLoading() {
  clearInterval(loadingInterval);
  loadingState.hidden = true;
}

function showError(message) {
  resetSections();
  errorState.hidden = false;
  errorMessage.textContent = message;
}

function isLikelyUrl(value) {
  try {
    const u = new URL(value.includes("://") ? value : `https://${value}`);
    return !!u.hostname && u.hostname.includes(".");
  } catch {
    return false;
  }
}

function normalizeUrl(value) {
  return value.includes("://") ? value : `https://${value}`;
}

// ---------- Rendering ----------

function renderScore(data) {
  scoreValue.textContent = data.score;
  scoreGrade.textContent = `GRADE ${data.grade}`;
  scoreUrl.textContent = data.url;

  const color = GRADE_COLORS[data.grade] || "#1F5C4D";
  dialFill.style.stroke = color;
  scoreGrade.style.color = color;
  scoreGrade.style.background = color + "1A";

  const circumference = 251;
  const offset = circumference - (circumference * data.score) / 100;
  // force reflow so the transition plays
  dialFill.style.transition = "none";
  dialFill.style.strokeDashoffset = circumference;
  void dialFill.offsetWidth;
  dialFill.style.transition = "";
  requestAnimationFrame(() => {
    dialFill.style.strokeDashoffset = offset;
  });

  const failCount = Object.values(data.categories)
    .flatMap((c) => c.checks)
    .filter((c) => c.status === "fail").length;
  const warnCount = Object.values(data.categories)
    .flatMap((c) => c.checks)
    .filter((c) => c.status === "warning").length;

  scoreSummary.textContent =
    failCount === 0 && warnCount === 0
      ? "Aucun problème détecté sur les critères analysés."
      : `${failCount} point${failCount === 1 ? "" : "s"} critique${failCount === 1 ? "" : "s"}, ${warnCount} avertissement${warnCount === 1 ? "" : "s"}.`;
}

function renderCategories(categories) {
  categoriesContainer.innerHTML = "";

  for (const [key, cat] of Object.entries(categories)) {
    const failCount = cat.checks.filter((c) => c.status === "fail").length;
    const warnCount = cat.checks.filter((c) => c.status === "warning").length;

    const el = document.createElement("div");
    el.className = "category";

    const countLabel =
      failCount > 0
        ? `${failCount} problème${failCount === 1 ? "" : "s"}`
        : warnCount > 0
        ? `${warnCount} avertissement${warnCount === 1 ? "" : "s"}`
        : "OK";

    el.innerHTML = `
      <button type="button" class="category-head">
        <span class="category-status status-${cat.status}"></span>
        <span class="category-title">${CATEGORY_LABELS[key] || key}</span>
        <span class="category-count">${countLabel}</span>
        <span class="category-chevron">▾</span>
      </button>
      <div class="category-body">
        ${cat.checks.map(renderCheckRow).join("")}
      </div>
    `;

    el.querySelector(".category-head").addEventListener("click", () => {
      el.classList.toggle("open");
    });

    categoriesContainer.appendChild(el);
  }

  // Ouvre automatiquement les catégories qui contiennent un problème
  categoriesContainer.querySelectorAll(".category").forEach((el, i) => {
    const key = Object.keys(categories)[i];
    if (categories[key].status !== "pass") el.classList.add("open");
  });
}

function renderCheckRow(check) {
  const cvesHtml =
    check.cves && check.cves.length > 0
      ? `<ul class="cve-list">${check.cves
          .map(
            (cve) => `
        <li class="cve-item">
          <span class="cve-severity">${escapeHtml(cve.id)} — ${escapeHtml(cve.severity)}${
              cve.score != null ? ` (${cve.score})` : ""
            }</span>
          <span>${escapeHtml(cve.description)}</span>
        </li>`
          )
          .join("")}</ul>`
      : "";

  const version = check.version ? ` <span style="color:var(--ink-muted)">v${escapeHtml(check.version)}</span>` : "";

  return `
    <div class="check-row">
      <span class="check-dot status-${check.status}"></span>
      <div>
        <p class="check-name">${escapeHtml(check.name)}${version}</p>
        <p class="check-message">${escapeHtml(check.message)}</p>
        ${cvesHtml}
      </div>
    </div>
  `;
}

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------- API calls ----------

async function runScan(rawUrl) {
  showLoading();

  try {
    const res = await fetch(`${API_URL}/scan?url=${encodeURIComponent(rawUrl)}`);
    const data = await res.json();

    if (!res.ok) {
      stopLoading();
      showError(data.error || "Une erreur inconnue est survenue pendant l'analyse.");
      return;
    }

    lastAuditJson = data;
    stopLoading();
    resultsSection.hidden = false;
    reportBody.innerHTML = '<p class="report-placeholder">Le rapport détaillé, en français clair, apparaîtra ici une fois généré.</p>';

    renderScore(data);
    renderCategories(data.categories);
  } catch (err) {
    stopLoading();
    showError(
      "Impossible de contacter le serveur d'analyse. Vérifie que le backend tourne bien sur " + API_URL + "."
    );
  }
}

async function generateReport() {
  if (!lastAuditJson) return;

  reportBtn.disabled = true;
  reportBtn.textContent = "Génération en cours…";
  reportBody.innerHTML = '<p class="report-placeholder">Rédaction du rapport en cours…</p>';

  try {
    const res = await fetch(`${API_URL}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastAuditJson),
    });
    const data = await res.json();

    if (!res.ok) {
      reportBody.innerHTML = `<p class="report-placeholder">Erreur : ${escapeHtml(data.error || "impossible de générer le rapport.")}</p>`;
    } else {
      const html = typeof marked !== "undefined" ? marked.parse(data.report || "") : escapeHtml(data.report || "");
      reportBody.innerHTML = html;
    }
  } catch (err) {
    reportBody.innerHTML = '<p class="report-placeholder">Erreur réseau lors de la génération du rapport.</p>';
  } finally {
    reportBtn.disabled = false;
    reportBtn.textContent = "Générer le rapport IA";
  }
}

// ---------- Events ----------

scanForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const value = urlInput.value.trim();

  if (!isLikelyUrl(value)) {
    formError.hidden = false;
    formError.textContent = "Entre une URL valide, par exemple https://exemple.com";
    return;
  }

  formError.hidden = true;
  runScan(normalizeUrl(value));
});

reportBtn.addEventListener("click", generateReport);