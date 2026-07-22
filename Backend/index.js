import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import dns from "node:dns/promises";
import net from "node:net";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const scanLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 20 });

// ---------- Helpers ----------

function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    return ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80");
  }
  const parts = ip.split(".").map(Number);
  if (parts[0] === 127) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (ip === "0.0.0.0") return true;
  return false;
}

async function assertUrlIsSafe(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("URL invalide");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Seuls http et https sont autorisés");
  }
  const hostname = parsed.hostname;
  if (hostname === "localhost") throw new Error("URL non autorisée");

  const results = await dns.lookup(hostname, { all: true });
  for (const r of results) {
    if (isPrivateIp(r.address)) {
      throw new Error("URL non autorisée (IP privée/interne)");
    }
  }
  return parsed;
}

function checkStatus(list, name, ok, okMsg, failMsg) {
  list.push({ name, status: ok ? "pass" : "fail", message: ok ? okMsg : failMsg });
}

function detectTechnologies(html, headers) {
  const found = [];

  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    const m = poweredBy.match(/^([A-Za-z.]+)\/?([\d.]+)?/);
    found.push({
      name: m ? m[1] : poweredBy,
      version: m && m[2] ? m[2] : null,
      status: "pass",
      message: "Détecté via header X-Powered-By",
    });
  }

  const serverHeader = headers.get("server");
  if (serverHeader) {
    const m = serverHeader.match(/^([A-Za-z-]+)\/?([\d.]+)?/);
    if (m && !found.some((f) => f.name.toLowerCase() === m[1].toLowerCase())) {
      found.push({ name: m[1], version: m[2] || null, status: "pass", message: "Détecté via header Server" });
    }
  }

  const generatorMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (generatorMatch) {
    const full = generatorMatch[1];
    const vm = full.match(/^([A-Za-z.]+)\s+([\d.]+)/);
    found.push({
      name: vm ? vm[1] : full,
      version: vm ? vm[2] : null,
      status: "pass",
      message: "Détecté via meta generator",
    });
  }

  const patterns = [
    ["WordPress", /wp-content|wp-includes/i, /wp-embed\.min\.js\?ver=([\d.]+)/i],
    ["jQuery", /jquery(\.min)?\.js/i, /jquery[-.]([\d.]+)(?:\.min)?\.js/i],
    ["React", /data-reactroot|react-dom/i, null],
    ["Next.js", /__NEXT_DATA__/i, null],
    ["Vue.js", /__vue__|data-v-/i, null],
    ["Google Analytics", /gtag\(|google-analytics\.com|googletagmanager\.com/i, null],
    ["Cloudflare", /cloudflare/i, null],
  ];
  for (const [name, presenceRegex, versionRegex] of patterns) {
    if (presenceRegex.test(html) && !found.some((f) => f.name.toLowerCase() === name.toLowerCase())) {
      let version = null;
      if (versionRegex) {
        const vMatch = html.match(versionRegex);
        if (vMatch) version = vMatch[1];
      }
      found.push({
        name,
        version,
        status: "pass",
        message: version ? `Détecté (version ${version})` : "Détecté (version non identifiable)",
      });
    }
  }

  if (found.length === 0) {
    found.push({ name: "Aucune technologie identifiée", version: null, status: "warning", message: "Détection limitée (méthode simplifiée)" });
  }
  return found;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchCvesForTech(name, version) {
  if (!version) return [];
  try {
    const query = encodeURIComponent(`${name} ${version}`);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=3`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    const vulns = data.vulnerabilities || [];
    return vulns.map((v) => {
      const cve = v.cve;
      const desc = cve.descriptions?.find((d) => d.lang === "en")?.value || "Description indisponible";
      const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV2?.[0]?.cvssData;
      return {
        id: cve.id,
        severity: metrics?.baseSeverity || "INCONNU",
        score: metrics?.baseScore ?? null,
        description: desc.slice(0, 200),
      };
    });
  } catch {
    return [];
  }
}

const SENSITIVE_PATHS = [
  ".env",
  ".git/config",
  ".git/HEAD",
  ".git/logs/HEAD",
  ".htaccess",
  ".htpasswd",
  "wp-config.php.bak",
  "config.php.bak",
  "config.php.old",
  "backup.zip",
  "backup.sql",
  "database.sql",
  "dump.sql",
  ".DS_Store",
  ".aws/credentials",
  "id_rsa",
  ".npmrc",
  "docker-compose.yml",
  "phpinfo.php",
  ".vscode/sftp.json",
  ".idea/workspace.xml",
  "server-status",
  "admin/config.php",
  "web.config",
  ".svn/entries",
  "error_log",
  "debug.log",
  ".well-known/security.txt",
];

async function checkSensitivePaths(origin) {
  const results = [];
  const batchSize = 5;
  for (let i = 0; i < SENSITIVE_PATHS.length; i += batchSize) {
    const batch = SENSITIVE_PATHS.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (path) => {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 4000);
          const res = await fetch(`${origin}/${path}`, { signal: controller.signal, redirect: "manual" });
          clearTimeout(timeout);
          const exposed = res.status === 200;
          if (path === ".well-known/security.txt") {
            return {
              name: path,
              status: exposed ? "pass" : "warning",
              message: exposed ? "Présent (bonne pratique)" : "Absent (bonne pratique recommandée, non bloquant)",
            };
          }
          return {
            name: path,
            status: exposed ? "fail" : "pass",
            message: exposed ? `Exposé publiquement (statut ${res.status})` : "Non accessible",
          };
        } catch {
          return { name: path, status: "pass", message: "Non accessible" };
        }
      })
    );
    results.push(...batchResults);
  }
  return results;
}

function computeScore(categories) {
  const weights = { headers: 40, cookies: 20, files: 15, technologies: 25 };
  let total = 0;
  let maxTotal = 0;
  for (const [key, weight] of Object.entries(weights)) {
    const checks = categories[key].checks;
    if (checks.length === 0) continue;
    const passCount = checks.filter((c) => c.status === "pass").length;
    const warnCount = checks.filter((c) => c.status === "warning").length;
    const ratio = (passCount + warnCount * 0.5) / checks.length;
    total += ratio * weight;
    maxTotal += weight;
  }
  const score = maxTotal > 0 ? Math.round((total / maxTotal) * 100) : 0;
  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  return { score, grade };
}

function categoryStatus(checks) {
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.some((c) => c.status === "warning")) return "warning";
  return "pass";
}

// ---------- Routes ----------

app.get("/scan", scanLimiter, async (req, res) => {
  const rawUrl = req.query.url;
  if (!rawUrl) return res.status(400).json({ error: "Paramètre 'url' manquant" });

  let parsedUrl;
  try {
    parsedUrl = await assertUrlIsSafe(rawUrl);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(parsedUrl.toString(), { signal: controller.signal });
    clearTimeout(timeout);

    const html = await response.text();
    const headers = response.headers;

    const headerChecks = [];
    checkStatus(headerChecks, "Content-Security-Policy", headers.has("content-security-policy"), "Présent", "En-tête absent");
    checkStatus(headerChecks, "Strict-Transport-Security", headers.has("strict-transport-security"), "Présent", "En-tête absent");
    checkStatus(headerChecks, "X-Frame-Options", headers.has("x-frame-options"), "Présent", "En-tête absent");
    checkStatus(headerChecks, "X-Content-Type-Options", headers.has("x-content-type-options"), "Présent", "En-tête absent");
    checkStatus(headerChecks, "Referrer-Policy", headers.has("referrer-policy"), "Présent", "En-tête absent");
    checkStatus(headerChecks, "Permissions-Policy", headers.has("permissions-policy"), "Présent", "En-tête absent");

    const rawSetCookie = headers.get("set-cookie") || "";
    const cookieChecks = [];
    if (rawSetCookie) {
      const cookieParts = rawSetCookie.split(/,(?=[^;]+?=)/);
      for (const c of cookieParts) {
        const name = c.split("=")[0].trim();
        const hasSecure = /secure/i.test(c);
        const hasHttpOnly = /httponly/i.test(c);
        const hasSameSite = /samesite/i.test(c);
        const okAll = hasSecure && hasHttpOnly && hasSameSite;
        const missing = [];
        if (!hasSecure) missing.push("Secure");
        if (!hasHttpOnly) missing.push("HttpOnly");
        if (!hasSameSite) missing.push("SameSite");
        cookieChecks.push({
          name,
          status: okAll ? "pass" : missing.length === 3 ? "fail" : "warning",
          message: okAll ? "Tous les flags de sécurité présents" : `Flags manquants: ${missing.join(", ")}`,
        });
      }
    } else {
      cookieChecks.push({ name: "Aucun cookie", status: "pass", message: "Aucun cookie détecté sur la réponse initiale" });
    }

    const origin = parsedUrl.origin;
    const fileChecks = await checkSensitivePaths(origin);

    const techChecks = detectTechnologies(html, headers);
    for (const tech of techChecks) {
      if (tech.version) {
        tech.cves = await fetchCvesForTech(tech.name, tech.version);
        await sleep(700); // respecte le rate limit NVD (pas de clé API)
      } else {
        tech.cves = [];
      }
    }

    const categories = {
      headers: { status: categoryStatus(headerChecks), checks: headerChecks },
      cookies: { status: categoryStatus(cookieChecks), checks: cookieChecks },
      files: { status: categoryStatus(fileChecks), checks: fileChecks },
      technologies: { status: categoryStatus(techChecks), checks: techChecks },
    };

    const { score, grade } = computeScore(categories);

    res.json({ url: parsedUrl.toString(), score, grade, categories });
  } catch (err) {
    res.status(500).json({ error: "Impossible d'analyser cette URL (" + err.message + ")" });
  }
});

app.post("/report", async (req, res) => {
  const auditJson = req.body;
  if (!auditJson || !auditJson.categories) {
    return res.status(400).json({ error: "Corps de requête invalide, JSON d'audit attendu" });
  }

  const systemPrompt =
    "Tu es un expert en cybersécurité qui rédige un rapport clair et pédagogique en français, " +
    "en Markdown, à partir d'un JSON d'audit de sécurité web. Explique chaque FAIL et WARNING en " +
    "une phrase simple, et donne une recommandation concrète pour chacun. Base-toi UNIQUEMENT sur " +
    "les données fournies dans le JSON, sans supposer d'informations absentes. Si le champ 'cves' " +
    "d'une technologie contient des entrées, résume leur sévérité (score CVSS) et donne une priorité " +
    "de correction. Ne mentionne JAMAIS de CVE qui n'est pas explicitement présente dans le JSON " +
    "fourni — n'invente jamais de faille non listée. Reste concis.";

  try {
    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": process.env.GEMINI_API_KEY,
        },
        body: JSON.stringify({
          system_instruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: "user", parts: [{ text: JSON.stringify(auditJson) }] }],
        }),
      }
    );

    const data = await response.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    res.json({ report: text || "Rapport indisponible." });
  } catch (err) {
    res.status(500).json({ error: "Erreur lors de la génération du rapport (" + err.message + ")" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API prête sur http://localhost:${PORT}`);
});