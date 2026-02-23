const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const querystring = require("querystring");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_ROOT = process.env.ANALYTICS_DATA_DIR || (fs.existsSync("/var/data") ? "/var/data" : path.join(ROOT, ".data"));
const EVENTS_FILE = path.join(DATA_ROOT, "analytics-events.jsonl");

const ADMIN_PATH = process.env.ADMIN_PATH || "/admin";
const LOGIN_PATH = `${ADMIN_PATH}/login`;
const LOGOUT_PATH = `${ADMIN_PATH}/logout`;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || "";
const ADMIN_COOKIE_NAME = "sv_admin";
const SESSION_TTL_SECONDS = 60 * 60 * 12;

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
};

const TRACKABLE_EVENTS = new Set(["page_view", "product_click", "play_start", "score_submit", "custom"]);

fs.mkdirSync(DATA_ROOT, { recursive: true });
if (!fs.existsSync(EVENTS_FILE)) {
  fs.writeFileSync(EVENTS_FILE, "", "utf8");
}

function send(res, statusCode, body, headers = {}) {
  res.writeHead(statusCode, headers);
  res.end(body);
}

function sendJson(res, statusCode, payload, headers = {}) {
  send(
    res,
    statusCode,
    JSON.stringify(payload),
    Object.assign(
      {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
      headers
    )
  );
}

function redirect(res, location) {
  send(res, 302, "", { Location: location, "Cache-Control": "no-store" });
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || "";
  const cookies = {};
  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const equalsIndex = trimmed.indexOf("=");
    if (equalsIndex === -1) continue;
    const key = trimmed.slice(0, equalsIndex).trim();
    const value = trimmed.slice(equalsIndex + 1).trim();
    cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

function isSecureRequest(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().toLowerCase();
  if (proto === "https") return true;
  const host = (req.headers.host || "").toString().toLowerCase();
  return host.includes("signorvale.com");
}

function setAdminCookie(res, req, token) {
  const flags = [
    `${ADMIN_COOKIE_NAME}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Strict",
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ];
  if (isSecureRequest(req)) flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}

function clearAdminCookie(res, req) {
  const flags = [
    `${ADMIN_COOKIE_NAME}=`,
    "HttpOnly",
    "Path=/",
    "SameSite=Strict",
    "Max-Age=0",
  ];
  if (isSecureRequest(req)) flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function isAdminConfigured() {
  return Boolean(ADMIN_PASSWORD && ADMIN_SESSION_SECRET);
}

function signValue(value) {
  return crypto.createHmac("sha256", ADMIN_SESSION_SECRET).update(value).digest("base64url");
}

function buildSessionToken(username) {
  const payload = {
    u: username,
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${encoded}.${signValue(encoded)}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes(".")) return null;
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) return null;
  const expected = signValue(encoded);
  if (!timingSafeEqual(signature, expected)) return null;
  let parsed = null;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  if (!parsed.exp || Date.now() > Number(parsed.exp)) return null;
  return parsed;
}

function isAuthenticated(req) {
  if (!isAdminConfigured()) return false;
  const cookies = parseCookies(req);
  const token = cookies[ADMIN_COOKIE_NAME];
  const session = verifySessionToken(token);
  return Boolean(session && session.u === ADMIN_USERNAME);
}

function parseBody(req, maxSizeBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > maxSizeBytes) {
        reject(new Error("Body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function safeString(value, maxLength = 160) {
  if (value == null) return "";
  return String(value).replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function getClientIp(req) {
  const cfIp = safeString(req.headers["cf-connecting-ip"], 80);
  if (cfIp) return cfIp;
  const forwarded = safeString(req.headers["x-forwarded-for"], 200);
  if (forwarded) return forwarded.split(",")[0].trim();
  return safeString(req.socket.remoteAddress || "unknown", 80);
}

function parseReferrerHost(value) {
  const input = safeString(value, 500);
  if (!input) return "";
  try {
    return new URL(input).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function appendEvent(event) {
  await fs.promises.appendFile(EVENTS_FILE, `${JSON.stringify(event)}\n`, "utf8");
}

function readEvents() {
  let raw = "";
  try {
    raw = fs.readFileSync(EVENTS_FILE, "utf8");
  } catch {
    return [];
  }

  const rows = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") rows.push(parsed);
    } catch {
      continue;
    }
  }
  return rows;
}

function roundTo(value, digits = 2) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function formatDay(d) {
  return new Date(d).toISOString().slice(0, 10);
}

function formatHour(d) {
  return new Date(d).toISOString().slice(0, 13) + ":00";
}

function aggregateAnalytics(events) {
  const now = Date.now();
  const oneDayMs = 24 * 60 * 60 * 1000;
  const fifteenMinutesMs = 15 * 60 * 1000;
  const oneHourMs = 60 * 60 * 1000;

  const visitors = new Set();
  const players = new Set();
  const activeVisitors = new Set();
  const trafficSources = new Map();
  const topProducts = new Map();
  const countries = new Map();
  const recentPlayersMap = new Map();
  const hourlyBuckets = new Map();
  const dailyBuckets = new Map();

  let pageViews = 0;
  let productClicks = 0;
  let playStarts = 0;
  let scoreSubmissions = 0;
  let totalScore = 0;
  let maxScore = null;

  for (const event of events) {
    const eventTs = Number(new Date(event.timestamp || 0));
    if (!Number.isFinite(eventTs)) continue;

    const anonId = safeString(event.anonId || event.userId || "", 80);
    const eventType = safeString(event.eventType || "", 40);
    const product = safeString(event.product || "Unknown Product", 120);
    const country = safeString(event.country || "Unknown", 40);
    const source = safeString(
      event.utmSource ? `utm:${event.utmSource}` : (event.referrerHost || "direct"),
      120
    );
    const score = typeof event.score === "number" ? event.score : null;

    if (anonId) {
      visitors.add(anonId);
      if (now - eventTs <= fifteenMinutesMs) activeVisitors.add(anonId);
    }

    if (eventType === "page_view") pageViews += 1;
    if (eventType === "product_click") productClicks += 1;
    if (eventType === "play_start") {
      playStarts += 1;
      if (anonId) players.add(anonId);
    }
    if (eventType === "score_submit") {
      scoreSubmissions += 1;
      if (anonId) players.add(anonId);
      if (score != null) {
        totalScore += score;
        maxScore = maxScore == null ? score : Math.max(maxScore, score);
      }
    }

    trafficSources.set(source, (trafficSources.get(source) || 0) + 1);
    countries.set(country, (countries.get(country) || 0) + 1);

    const productStats = topProducts.get(product) || {
      name: product,
      clicks: 0,
      plays: 0,
      scores: 0,
      totalScore: 0,
      maxScore: null,
      players: new Set(),
    };
    if (eventType === "product_click") productStats.clicks += 1;
    if (eventType === "play_start") productStats.plays += 1;
    if (eventType === "score_submit") {
      productStats.scores += 1;
      if (score != null) {
        productStats.totalScore += score;
        productStats.maxScore = productStats.maxScore == null ? score : Math.max(productStats.maxScore, score);
      }
    }
    if (anonId && (eventType === "play_start" || eventType === "score_submit")) {
      productStats.players.add(anonId);
    }
    topProducts.set(product, productStats);

    const hourKey = formatHour(eventTs);
    hourlyBuckets.set(hourKey, (hourlyBuckets.get(hourKey) || 0) + 1);

    const dayKey = formatDay(eventTs);
    const dayStats = dailyBuckets.get(dayKey) || { day: dayKey, events: 0, plays: 0, visitors: new Set() };
    dayStats.events += 1;
    if (eventType === "play_start" || eventType === "score_submit") dayStats.plays += 1;
    if (anonId) dayStats.visitors.add(anonId);
    dailyBuckets.set(dayKey, dayStats);

    if (anonId && now - eventTs <= oneHourMs && (eventType === "play_start" || eventType === "score_submit")) {
      const existing = recentPlayersMap.get(anonId);
      if (!existing || eventTs > Number(new Date(existing.lastSeen))) {
        recentPlayersMap.set(anonId, {
          user: anonId,
          product,
          country,
          lastSeen: new Date(eventTs).toISOString(),
          score: score != null ? score : existing?.score ?? null,
        });
      }
    }
  }

  const last24Hours = [];
  for (let i = 23; i >= 0; i -= 1) {
    const bucketDate = new Date(now - i * oneHourMs);
    const label = formatHour(bucketDate);
    last24Hours.push({
      hour: label,
      events: hourlyBuckets.get(label) || 0,
    });
  }

  const last14Days = [];
  for (let i = 13; i >= 0; i -= 1) {
    const dayDate = new Date(now - i * oneDayMs);
    const label = formatDay(dayDate);
    const dayStats = dailyBuckets.get(label);
    last14Days.push({
      day: label,
      events: dayStats?.events || 0,
      plays: dayStats?.plays || 0,
      visitors: dayStats ? dayStats.visitors.size : 0,
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    totals: {
      events: events.length,
      visitors: visitors.size,
      activeNow: activeVisitors.size,
      players: players.size,
      pageViews,
      productClicks,
      playStarts,
      scoreSubmissions,
      avgScore: scoreSubmissions > 0 ? roundTo(totalScore / scoreSubmissions, 2) : null,
      maxScore,
    },
    trafficSources: [...trafficSources.entries()]
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    countries: [...countries.entries()]
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    topProducts: [...topProducts.values()]
      .map((item) => ({
        name: item.name,
        clicks: item.clicks,
        plays: item.plays,
        scores: item.scores,
        avgScore: item.scores > 0 ? roundTo(item.totalScore / item.scores, 2) : null,
        maxScore: item.maxScore,
        uniquePlayers: item.players.size,
      }))
      .sort((a, b) => b.plays + b.clicks - (a.plays + a.clicks))
      .slice(0, 15),
    recentPlayers: [...recentPlayersMap.values()]
      .sort((a, b) => Number(new Date(b.lastSeen)) - Number(new Date(a.lastSeen)))
      .slice(0, 20),
    hourly: last24Hours,
    daily: last14Days,
  };
}

function resolvePublicPath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split("?")[0]);
  const requested = decoded === "/" ? "/index.html" : decoded;
  const fullPath = path.normalize(path.join(ROOT, requested));
  if (!fullPath.startsWith(ROOT)) return null;

  const blockedRoots = [path.join(ROOT, ".git"), path.join(ROOT, ".data")];
  if (blockedRoots.some((prefix) => fullPath.startsWith(prefix))) return null;

  return fullPath;
}

function getSecurityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  };
}

function renderAdminLoginPage(message = "") {
  const safeMessage = message ? `<p class="msg">${message}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex,nofollow" />
  <title>Signor Vale Admin Login</title>
  <style>
    :root { --bg:#090d14; --card:#111827; --text:#e6edf7; --muted:#9fb0c8; --line:#22314b; --accent:#29c7ac; --accent-2:#40e0d0; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; font-family:ui-sans-serif, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      background:
        radial-gradient(circle at 10% 10%, rgba(64,224,208,0.2), transparent 42%),
        radial-gradient(circle at 90% 0%, rgba(41,199,172,0.16), transparent 35%),
        linear-gradient(160deg, #06080d 0%, #0e1522 58%, #131d2f 100%);
      color:var(--text); padding:24px; }
    .card { width:min(460px, 100%); background:rgba(17,24,39,0.86); border:1px solid var(--line); border-radius:18px; padding:30px 24px; backdrop-filter: blur(8px); }
    h1 { margin:0 0 8px; font-size:28px; letter-spacing:-0.02em; }
    p { margin:0 0 18px; color:var(--muted); font-size:14px; }
    .msg { border:1px solid #7d2d2d; background:#2a1616; color:#ffb4b4; padding:10px 12px; border-radius:10px; margin-bottom:14px; }
    label { display:block; font-size:12px; text-transform:uppercase; letter-spacing:0.1em; color:var(--muted); margin:14px 0 7px; }
    input { width:100%; background:#0b1220; border:1px solid #27344f; color:var(--text); border-radius:10px; padding:12px; font-size:14px; }
    input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(64,224,208,0.18); }
    button { margin-top:16px; width:100%; border:0; border-radius:10px; padding:12px; font-size:14px; font-weight:700; cursor:pointer;
      background:linear-gradient(135deg, var(--accent), var(--accent-2)); color:#052420; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Private Analytics</h1>
    <p>Sign in to access your admin dashboard.</p>
    ${safeMessage}
    <form method="post" action="${LOGIN_PATH}" autocomplete="off">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" required />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required />
      <button type="submit">Enter Dashboard</button>
    </form>
  </main>
</body>
</html>`;
}

function renderAdminDashboardPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex,nofollow" />
  <title>Signor Vale Analytics</title>
  <style>
    :root { --bg:#071018; --panel:#101b2b; --panel-2:#14233a; --line:#233754; --text:#e9f2ff; --muted:#9ab0cc; --mint:#2fd8c0; --blue:#5db8ff; --rose:#ff6e91; --amber:#ffc770; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--text); font-family:ui-sans-serif, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      background:
        radial-gradient(circle at 8% 0%, rgba(47,216,192,0.18), transparent 40%),
        radial-gradient(circle at 98% 10%, rgba(93,184,255,0.18), transparent 35%),
        linear-gradient(160deg, #050b12 0%, #09121e 46%, #0b1521 100%);
      min-height:100vh; }
    .shell { width:min(1240px, 100%); margin:0 auto; padding:28px 20px 40px; }
    .top { display:flex; justify-content:space-between; align-items:flex-end; gap:16px; margin-bottom:22px; }
    .title h1 { margin:0; font-size:34px; letter-spacing:-0.03em; }
    .title p { margin:6px 0 0; color:var(--muted); font-size:14px; }
    .top-right { display:flex; align-items:center; gap:12px; color:var(--muted); font-size:13px; }
    .logout button { border:1px solid var(--line); color:var(--text); background:var(--panel); border-radius:10px; padding:10px 12px; cursor:pointer; }
    .grid { display:grid; gap:12px; }
    .kpis { grid-template-columns:repeat(6, minmax(0, 1fr)); margin-bottom:12px; }
    .card { background:linear-gradient(165deg, rgba(16,27,43,0.96), rgba(13,22,35,0.94)); border:1px solid var(--line); border-radius:14px; padding:14px; }
    .kpi-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.12em; }
    .kpi-value { margin-top:8px; font-size:28px; font-weight:800; letter-spacing:-0.02em; }
    .kpi-sub { margin-top:6px; font-size:12px; color:var(--muted); }
    .layout { grid-template-columns:2fr 1fr; align-items:start; }
    h2 { margin:0 0 12px; font-size:16px; letter-spacing:-0.01em; }
    .bars { display:grid; gap:8px; }
    .bar-row { display:grid; grid-template-columns:120px 1fr auto; gap:10px; align-items:center; font-size:12px; }
    .bar-label { color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .bar-wrap { height:10px; background:#0a1320; border-radius:999px; overflow:hidden; border:1px solid #1d2c44; }
    .bar-fill { height:100%; background:linear-gradient(90deg, var(--mint), var(--blue)); }
    .bar-value { font-weight:700; font-size:12px; min-width:24px; text-align:right; }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    th, td { padding:10px 8px; border-bottom:1px solid #1b2a43; text-align:left; vertical-align:middle; }
    th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:0.08em; }
    .chip { display:inline-block; border:1px solid #2b4064; background:#0f1b2c; color:#bcd2ef; border-radius:999px; padding:4px 8px; font-size:11px; }
    .timeline { display:grid; grid-template-columns:repeat(24, minmax(8px, 1fr)); gap:4px; align-items:end; min-height:90px; }
    .stick { background:linear-gradient(180deg, var(--blue), var(--mint)); border-radius:4px 4px 2px 2px; min-height:4px; opacity:0.9; }
    .tiny { color:var(--muted); font-size:11px; margin-top:8px; }
    .empty { color:var(--muted); font-size:13px; padding:8px 0; }
    @media (max-width: 1080px) {
      .kpis { grid-template-columns:repeat(3, minmax(0, 1fr)); }
      .layout { grid-template-columns:1fr; }
    }
    @media (max-width: 660px) {
      .kpis { grid-template-columns:repeat(2, minmax(0, 1fr)); }
      .top { flex-direction:column; align-items:flex-start; }
      .bar-row { grid-template-columns:100px 1fr auto; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="top">
      <div class="title">
        <h1>Analytics Command Center</h1>
        <p>Private admin view for Signor Vale traffic and gameplay signals.</p>
      </div>
      <div class="top-right">
        <span id="last-updated">Loading...</span>
        <form class="logout" method="post" action="${LOGOUT_PATH}">
          <button type="submit">Logout</button>
        </form>
      </div>
    </header>

    <section class="grid kpis" id="kpi-grid"></section>

    <section class="grid layout">
      <article class="card">
        <h2>Top Products</h2>
        <div id="top-products"></div>
      </article>
      <article class="card">
        <h2>Traffic Sources</h2>
        <div id="traffic-sources"></div>
      </article>
      <article class="card">
        <h2>Live Players (Last 60m)</h2>
        <div id="recent-players"></div>
      </article>
      <article class="card">
        <h2>Events Last 24 Hours</h2>
        <div id="hourly-chart"></div>
      </article>
      <article class="card">
        <h2>Top Countries</h2>
        <div id="countries"></div>
      </article>
      <article class="card">
        <h2>Daily Trend (14d)</h2>
        <div id="daily-trend"></div>
      </article>
    </section>
  </div>

  <script>
    const numberFmt = new Intl.NumberFormat();
    const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
    const relativeFmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

    function safe(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function fmtNumber(value) {
      return value == null ? "—" : numberFmt.format(value);
    }

    function fmtRelative(isoString) {
      if (!isoString) return "—";
      const then = new Date(isoString).getTime();
      if (!Number.isFinite(then)) return "—";
      const diffSec = Math.round((then - Date.now()) / 1000);
      if (Math.abs(diffSec) < 60) return "just now";
      if (Math.abs(diffSec) < 3600) return relativeFmt.format(Math.round(diffSec / 60), "minute");
      return relativeFmt.format(Math.round(diffSec / 3600), "hour");
    }

    function renderKpis(data) {
      const totals = data.totals || {};
      const entries = [
        ["Visitors", totals.visitors, "Unique anonymous users"],
        ["Active Now", totals.activeNow, "Seen in last 15 minutes"],
        ["Players", totals.players, "Unique users who played"],
        ["Plays", totals.playStarts, "Play starts captured"],
        ["Avg Score", totals.avgScore, "Across score submissions"],
        ["Max Score", totals.maxScore, "Highest recorded score"]
      ];
      document.getElementById("kpi-grid").innerHTML = entries.map(([label, value, sub]) => \`
        <article class="card">
          <div class="kpi-label">\${safe(label)}</div>
          <div class="kpi-value">\${safe(fmtNumber(value))}</div>
          <div class="kpi-sub">\${safe(sub)}</div>
        </article>
      \`).join("");
    }

    function renderBars(targetId, rows, keyName) {
      const root = document.getElementById(targetId);
      if (!rows || !rows.length) {
        root.innerHTML = '<div class="empty">No data yet</div>';
        return;
      }
      const max = Math.max(...rows.map((x) => Number(x.count || 0)), 1);
      root.innerHTML = '<div class="bars">' + rows.map((row) => {
        const label = safe(row[keyName] || "unknown");
        const count = Number(row.count || 0);
        const width = Math.max(4, Math.round((count / max) * 100));
        return \`
          <div class="bar-row">
            <div class="bar-label">\${label}</div>
            <div class="bar-wrap"><div class="bar-fill" style="width:\${width}%"></div></div>
            <div class="bar-value">\${safe(fmtNumber(count))}</div>
          </div>
        \`;
      }).join("") + "</div>";
    }

    function renderTopProducts(data) {
      const rows = data.topProducts || [];
      const target = document.getElementById("top-products");
      if (!rows.length) {
        target.innerHTML = '<div class="empty">No product interactions yet</div>';
        return;
      }
      target.innerHTML = \`
        <table>
          <thead>
            <tr>
              <th>Product</th>
              <th>Clicks</th>
              <th>Plays</th>
              <th>Players</th>
              <th>Avg Score</th>
              <th>Max</th>
            </tr>
          </thead>
          <tbody>
            \${rows.map((row) => \`
              <tr>
                <td>\${safe(row.name)}</td>
                <td>\${safe(fmtNumber(row.clicks))}</td>
                <td>\${safe(fmtNumber(row.plays))}</td>
                <td>\${safe(fmtNumber(row.uniquePlayers))}</td>
                <td>\${safe(fmtNumber(row.avgScore))}</td>
                <td>\${safe(fmtNumber(row.maxScore))}</td>
              </tr>
            \`).join("")}
          </tbody>
        </table>
      \`;
    }

    function renderRecentPlayers(data) {
      const rows = data.recentPlayers || [];
      const target = document.getElementById("recent-players");
      if (!rows.length) {
        target.innerHTML = '<div class="empty">No active players in the last hour</div>';
        return;
      }
      target.innerHTML = \`
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Product</th>
              <th>Score</th>
              <th>Country</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            \${rows.map((row) => {
              const shortUser = row.user.length > 12 ? row.user.slice(0, 12) + "…" : row.user;
              return \`
                <tr>
                  <td><span class="chip">\${safe(shortUser)}</span></td>
                  <td>\${safe(row.product || "—")}</td>
                  <td>\${safe(fmtNumber(row.score))}</td>
                  <td>\${safe(row.country || "—")}</td>
                  <td title="\${safe(row.lastSeen)}">\${safe(fmtRelative(row.lastSeen))}</td>
                </tr>
              \`;
            }).join("")}
          </tbody>
        </table>
      \`;
    }

    function renderHourly(data) {
      const rows = data.hourly || [];
      const target = document.getElementById("hourly-chart");
      if (!rows.length) {
        target.innerHTML = '<div class="empty">No hourly data yet</div>';
        return;
      }
      const max = Math.max(...rows.map((x) => Number(x.events || 0)), 1);
      target.innerHTML = \`
        <div class="timeline">
          \${rows.map((row) => {
            const height = Math.max(6, Math.round((Number(row.events || 0) / max) * 88));
            return \`<div class="stick" style="height:\${height}px" title="\${safe(row.hour)}: \${safe(String(row.events))} events"></div>\`;
          }).join("")}
        </div>
        <div class="tiny">Each bar represents one hour. Rightmost bar is the current hour.</div>
      \`;
    }

    function renderDaily(data) {
      const rows = data.daily || [];
      const target = document.getElementById("daily-trend");
      if (!rows.length) {
        target.innerHTML = '<div class="empty">No daily trend yet</div>';
        return;
      }
      target.innerHTML = \`
        <table>
          <thead>
            <tr>
              <th>Day</th>
              <th>Visitors</th>
              <th>Events</th>
              <th>Plays</th>
            </tr>
          </thead>
          <tbody>
            \${rows.map((row) => \`
              <tr>
                <td>\${safe(row.day)}</td>
                <td>\${safe(fmtNumber(row.visitors))}</td>
                <td>\${safe(fmtNumber(row.events))}</td>
                <td>\${safe(fmtNumber(row.plays))}</td>
              </tr>
            \`).join("")}
          </tbody>
        </table>
      \`;
    }

    async function loadAnalytics() {
      const response = await fetch("/api/admin/analytics", { cache: "no-store" });
      if (response.status === 401) {
        window.location.href = "${LOGIN_PATH}";
        return;
      }
      if (!response.ok) throw new Error("Failed to load analytics");

      const data = await response.json();
      renderKpis(data);
      renderBars("traffic-sources", data.trafficSources || [], "source");
      renderBars("countries", data.countries || [], "country");
      renderTopProducts(data);
      renderRecentPlayers(data);
      renderHourly(data);
      renderDaily(data);

      const generatedAt = data.generatedAt ? new Date(data.generatedAt) : new Date();
      document.getElementById("last-updated").textContent = "Updated " + dateTimeFmt.format(generatedAt);
    }

    async function refreshLoop() {
      try {
        await loadAnalytics();
      } catch (error) {
        console.error(error);
        document.getElementById("last-updated").textContent = "Failed to refresh";
      }
    }

    refreshLoop();
    setInterval(refreshLoop, 30000);
  </script>
</body>
</html>`;
}

function buildTrackEvent(req, payload, reqUrl) {
  const eventType = safeString(payload.eventType, 40);
  if (!TRACKABLE_EVENTS.has(eventType)) return null;

  const anonId = safeString(payload.anonId || payload.userId, 80);
  const scoreValue = payload.score == null ? null : Number(payload.score);
  const score = Number.isFinite(scoreValue) ? roundTo(scoreValue, 2) : null;
  const countryHeader = safeString(req.headers["cf-ipcountry"], 20);
  const referrerHost =
    parseReferrerHost(payload.referrer || req.headers.referer || "") || safeString(payload.referrerHost, 120);

  return {
    timestamp: new Date().toISOString(),
    eventType,
    anonId,
    category: safeString(payload.category, 80),
    product: safeString(payload.product, 120),
    cta: safeString(payload.cta, 40),
    path: safeString(payload.path || reqUrl.pathname, 120),
    score,
    utmSource: safeString(payload.utmSource, 80),
    utmMedium: safeString(payload.utmMedium, 80),
    utmCampaign: safeString(payload.utmCampaign, 120),
    referrer: safeString(payload.referrer || req.headers.referer || "", 500),
    referrerHost,
    country: countryHeader || safeString(payload.country, 40) || "Unknown",
    ip: getClientIp(req),
    userAgent: safeString(req.headers["user-agent"] || "", 240),
  };
}

function serveStatic(req, res, pathname) {
  const filePath = resolvePublicPath(pathname);
  if (!filePath) {
    send(res, 400, "Bad request", {
      "Content-Type": "text/plain; charset=utf-8",
      ...getSecurityHeaders(),
    });
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (pathname !== "/" && pathname !== "/index.html") {
        fs.readFile(path.join(ROOT, "index.html"), (indexErr, indexData) => {
          if (indexErr) {
            send(res, 404, "Not found", {
              "Content-Type": "text/plain; charset=utf-8",
              ...getSecurityHeaders(),
            });
            return;
          }
          send(res, 200, indexData, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            ...getSecurityHeaders(),
          });
        });
        return;
      }

      send(res, 404, "Not found", {
        "Content-Type": "text/plain; charset=utf-8",
        ...getSecurityHeaders(),
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";
    send(res, 200, data, {
      "Content-Type": contentType,
      "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=300",
      ...getSecurityHeaders(),
    });
  });
}

const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const pathname = requestUrl.pathname;
  const method = (req.method || "GET").toUpperCase();

  try {
    if (pathname === "/health") {
      sendJson(res, 200, { ok: true, adminConfigured: isAdminConfigured() }, getSecurityHeaders());
      return;
    }

    if (pathname === "/api/track") {
      if (method === "OPTIONS") {
        send(res, 204, "", {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Methods": "POST,OPTIONS",
        });
        return;
      }
      if (method !== "POST") {
        sendJson(res, 405, { error: "Method not allowed" }, getSecurityHeaders());
        return;
      }

      const bodyRaw = await parseBody(req);
      let payload = {};
      try {
        payload = bodyRaw ? JSON.parse(bodyRaw) : {};
      } catch {
        sendJson(res, 400, { error: "Invalid JSON" }, getSecurityHeaders());
        return;
      }

      const event = buildTrackEvent(req, payload, requestUrl);
      if (!event) {
        sendJson(res, 400, { error: "Invalid event type" }, getSecurityHeaders());
        return;
      }

      await appendEvent(event);
      sendJson(res, 202, { ok: true }, getSecurityHeaders());
      return;
    }

    if (pathname === LOGIN_PATH) {
      if (!isAdminConfigured()) {
        send(
          res,
          503,
          "Admin login disabled. Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET.",
          { "Content-Type": "text/plain; charset=utf-8", ...getSecurityHeaders() }
        );
        return;
      }

      if (method === "GET") {
        if (isAuthenticated(req)) {
          redirect(res, ADMIN_PATH);
          return;
        }
        send(res, 200, renderAdminLoginPage(), {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          ...getSecurityHeaders(),
        });
        return;
      }

      if (method === "POST") {
        const body = await parseBody(req);
        const parsed = querystring.parse(body);
        const username = safeString(parsed.username, 80);
        const password = safeString(parsed.password, 200);
        const validUser = timingSafeEqual(username, ADMIN_USERNAME);
        const validPass = timingSafeEqual(password, ADMIN_PASSWORD);

        if (!validUser || !validPass) {
          send(res, 401, renderAdminLoginPage("Invalid credentials"), {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            ...getSecurityHeaders(),
          });
          return;
        }

        const token = buildSessionToken(username);
        setAdminCookie(res, req, token);
        redirect(res, ADMIN_PATH);
        return;
      }

      sendJson(res, 405, { error: "Method not allowed" }, getSecurityHeaders());
      return;
    }

    if (pathname === LOGOUT_PATH) {
      if (method !== "POST") {
        sendJson(res, 405, { error: "Method not allowed" }, getSecurityHeaders());
        return;
      }
      clearAdminCookie(res, req);
      redirect(res, LOGIN_PATH);
      return;
    }

    if (pathname === ADMIN_PATH || pathname === `${ADMIN_PATH}/`) {
      if (!isAuthenticated(req)) {
        redirect(res, LOGIN_PATH);
        return;
      }

      send(res, 200, renderAdminDashboardPage(), {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        ...getSecurityHeaders(),
      });
      return;
    }

    if (pathname === "/api/admin/analytics") {
      if (!isAuthenticated(req)) {
        sendJson(res, 401, { error: "Unauthorized" }, getSecurityHeaders());
        return;
      }
      if (method !== "GET") {
        sendJson(res, 405, { error: "Method not allowed" }, getSecurityHeaders());
        return;
      }

      const events = readEvents();
      const analytics = aggregateAnalytics(events);
      sendJson(res, 200, analytics, getSecurityHeaders());
      return;
    }

    if (pathname.startsWith("/api/admin/")) {
      if (!isAuthenticated(req)) {
        sendJson(res, 401, { error: "Unauthorized" }, getSecurityHeaders());
        return;
      }
      sendJson(res, 404, { error: "Not found" }, getSecurityHeaders());
      return;
    }

    if (pathname.startsWith(ADMIN_PATH) || pathname === "/admin.html") {
      sendJson(res, 404, { error: "Not found" }, getSecurityHeaders());
      return;
    }

    serveStatic(req, res, pathname);
  } catch (error) {
    console.error("Request failed:", error);
    sendJson(res, 500, { error: "Internal server error" }, getSecurityHeaders());
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
  if (!isAdminConfigured()) {
    console.log("Admin dashboard is disabled. Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET to enable it.");
  }
});
