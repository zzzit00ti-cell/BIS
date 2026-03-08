/* BIS data store + auth (static HTML, no backend).
   Passwords are hashed (PBKDF2-SHA256); a static frontend cannot provide server-grade security. */
(function () {
  "use strict";

  const DB_KEY = "bis_db_v2";
  const SESSION_KEY = "bis_session_v1";

  function nowIso() {
    return new Date().toISOString();
  }

  function safeJsonParse(str, fallback) {
    try {
      return JSON.parse(str);
    } catch {
      return fallback;
    }
  }

  function bytesToB64(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function sha256Base64(text) {
    const enc = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return bytesToB64(new Uint8Array(digest));
  }

  async function pbkdf2Base64(password, saltBytes, iterations) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
      keyMaterial,
      256
    );
    return bytesToB64(new Uint8Array(bits));
  }

  async function hashPassword(password, saltB64) {
    // PBKDF2 requires SubtleCrypto (usually available on modern browsers).
    // If unavailable, fall back to SHA256(salt:password).
    const saltBytes = b64ToBytes(saltB64);
    if (crypto?.subtle?.deriveBits) {
      return pbkdf2Base64(password, saltBytes, 210_000);
    }
    return sha256Base64(`${saltB64}:${password}`);
  }

  function randomSaltB64() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return bytesToB64(bytes);
  }

  function normalizeUsername(u) {
    return String(u || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "");
  }

  function newId(prefix) {
    // Example: STD-20260226-8F3A2C
    const date = new Date();
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, "0");
    const d = String(date.getDate()).padStart(2, "0");
    const rand = Math.random().toString(16).slice(2, 8).toUpperCase();
    return `${prefix}-${y}${m}${d}-${rand}`;
  }

  function emptyDb() {
    return {
      version: 1,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      accounts: [],
      announcements: [],
      audit: [],
    };
  }

  function loadDb() {
    const raw = localStorage.getItem(DB_KEY);
    const db = raw ? safeJsonParse(raw, null) : null;
    if (!db || typeof db !== "object") return emptyDb();
    if (!Array.isArray(db.accounts)) db.accounts = [];
    if (!Array.isArray(db.announcements)) db.announcements = [];
    if (!Array.isArray(db.audit)) db.audit = [];
    if (typeof db.version !== "number") db.version = 1;
    if (!db.createdAt) db.createdAt = nowIso();
    if (!db.updatedAt) db.updatedAt = nowIso();
    return db;
  }

  function saveDb(db) {
    db.updatedAt = nowIso();
    localStorage.setItem(DB_KEY, JSON.stringify(db));
  }

  let seedPromise = null;
  async function seedInitialAccountsIfEmpty() {
    const db = loadDb();
    if (db.accounts && db.accounts.length > 0) return;
    const seeds = [
      { id: "ADM-0001", role: "admin", username: "admin", name: "System Administrator", tempPassword: "Admin@2026" },
      { id: "TCH-1001", role: "teacher", username: "daniel.math", name: "Mr Daniel Bekele", subject: "Mathematics", tempPassword: "Teacher@2026" },
      { id: "TCH-1002", role: "teacher", username: "eleni.english", name: "Ms Eleni Tesfaye", subject: "English Literature", tempPassword: "Teacher@2026" },
      { id: "STD-2001", role: "student", username: "abebech.10a", name: "Abebech Kebede", grade: "10", teacherName: "Mr Daniel Bekele", marks: { total: "93%", details: [] }, tempPassword: "Student@2026" },
      { id: "STD-2002", role: "student", username: "chala.10b", name: "Chala Dibaba", grade: "10", teacherName: "Ms Eleni Tesfaye", marks: { total: "88%", details: [] }, tempPassword: "Student@2026" },
      { id: "STD-2003", role: "student", username: "fatuma.11a", name: "Fatuma Ali", grade: "11", teacherName: "Mr Daniel Bekele", marks: { total: "95%", details: [] }, tempPassword: "Student@2026" },
    ];
    for (const s of seeds) {
      try {
        await createAccount(
          { id: s.id, role: s.role, username: s.username, name: s.name, grade: s.grade, teacherName: s.teacherName, marks: s.marks, subject: s.subject, tempPassword: s.tempPassword },
          { who: "system-seed" }
        );
      } catch (e) {
        console.warn("Seed skip:", s.username, e);
      }
    }
    const dbAfter = loadDb();
    dbAfter.audit.push({ at: nowIso(), action: "seed_initial_accounts", who: "system" });
    saveDb(dbAfter);
  }
  function ensureSeeded() {
    if (!seedPromise) seedPromise = seedInitialAccountsIfEmpty();
    return seedPromise;
  }

  function getSession() {
    const raw = sessionStorage.getItem(SESSION_KEY);
    const s = raw ? safeJsonParse(raw, null) : null;
    if (!s || typeof s !== "object") return null;
    if (!s.userId) return null;
    return s;
  }

  function setSession(userId) {
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({ userId, createdAt: nowIso() })
    );
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  function getCurrentAccount() {
    const s = getSession();
    if (!s) return null;
    const db = loadDb();
    return db.accounts.find((a) => a.id === s.userId) || null;
  }

  function requireAuth(options) {
    const { role, redirectTo = "login.html" } = options || {};
    const acct = getCurrentAccount();
    if (!acct || acct.status !== "Active") {
      clearSession();
      window.location.href = redirectTo;
      return null;
    }
    if (role && acct.role !== role) {
      window.location.href = redirectTo;
      return null;
    }
    return acct;
  }

  function sanitizeText(s) {
    return String(s || "").trim();
  }

  function validatePassword(pw) {
    const p = String(pw || "");
    if (p.length < 8) return "Password must be at least 8 characters.";
    if (!/[0-9]/.test(p)) return "Password must include at least 1 number.";
    if (!/[A-Za-z]/.test(p)) return "Password must include letters.";
    return null;
  }

  async function verifyLogin(username, password) {
    await ensureSeeded();
    const db = loadDb();
    const u = normalizeUsername(username);
    let acct = db.accounts.find((a) => normalizeUsername(a.username) === u);

    if (acct && acct.status === "Active" && acct.password?.saltB64 && acct.password?.hashB64) {
      const hashB64 = await hashPassword(password, acct.password.saltB64);
      if (hashB64 === acct.password.hashB64) {
        return { ok: true, account: acct };
      }
    }

    const hasAdmin = db.accounts.some((a) => a.role === "admin");
    if (!hasAdmin && u === "admin" && password === "Admin@2026") {
      const created = await createAccount(
        { role: "admin", username: "admin", name: "System Administrator", tempPassword: password },
        { who: "system-fallback" }
      );
      return { ok: true, account: created.account };
    }

    return { ok: false, reason: "Invalid login." };
  }

  async function setAccountPassword(accountId, newPassword, options) {
    const db = loadDb();
    const acct = db.accounts.find((a) => a.id === accountId);
    if (!acct) throw new Error("Account not found.");
    const err = validatePassword(newPassword);
    if (err) throw new Error(err);
    const salt = randomSaltB64();
    const hashB64 = await hashPassword(newPassword, salt);
    acct.password = {
      saltB64: salt,
      hashB64,
      updatedAt: nowIso(),
      mustChangePassword: Boolean(options?.mustChangePassword),
    };
    acct.updatedAt = nowIso();
    db.audit.push({ at: nowIso(), action: "password_set", who: options?.who || "system", target: accountId });
    saveDb(db);
    return acct;
  }

  async function createAccount(payload, options) {
    const db = loadDb();
    const role = payload?.role;
    if (!["student", "teacher", "admin"].includes(role)) {
      throw new Error("Invalid role.");
    }
    const username = normalizeUsername(payload?.username || payload?.id || payload?.name);
    if (!username) throw new Error("Username is required.");
    if (db.accounts.some((a) => normalizeUsername(a.username) === username)) {
      throw new Error("Username already exists.");
    }

    const accountId =
      payload?.id ||
      newId(role === "student" ? "STD" : role === "teacher" ? "TCH" : "ADM");

    const acct = {
      id: accountId,
      role,
      username,
      displayName: sanitizeText(payload?.name || payload?.displayName || username),
      status: payload?.status || "Active",
      photoDataUrl: payload?.photoDataUrl || "",
      profile: {
        // student fields
        grade: payload?.grade ?? "",
        age: payload?.age ?? "",
        sex: payload?.sex ?? "",
        teacherName: payload?.teacherName ?? "",
        marks: payload?.marks ?? { total: "", details: [] },
        // teacher fields
        subject: payload?.subject ?? payload?.detail ?? "",
      },
      password: {
        saltB64: randomSaltB64(),
        hashB64: "", // set below
        updatedAt: nowIso(),
        mustChangePassword: true,
      },
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };

    db.accounts.push(acct);
    db.audit.push({ at: nowIso(), action: "account_created", who: options?.who || "admin", target: accountId });
    saveDb(db);

    const tempPassword = payload?.tempPassword || "ChangeMe123";
    await setAccountPassword(accountId, tempPassword, { mustChangePassword: true, who: options?.who || "admin" });
    return { account: loadDb().accounts.find((a) => a.id === accountId), tempPassword };
  }

  function listAccounts() {
    const db = loadDb();
    return db.accounts.slice();
  }

  function updateAccountProfile(accountId, patch, options) {
    const db = loadDb();
    const acct = db.accounts.find((a) => a.id === accountId);
    if (!acct) throw new Error("Account not found.");
    if (patch.displayName != null) acct.displayName = sanitizeText(patch.displayName);
    if (patch.photoDataUrl != null) acct.photoDataUrl = patch.photoDataUrl;
    if (patch.status != null) acct.status = patch.status;
    if (patch.username != null) acct.username = normalizeUsername(patch.username);
    acct.profile = { ...acct.profile, ...(patch.profile || {}) };
    acct.updatedAt = nowIso();
    db.audit.push({ at: nowIso(), action: "account_updated", who: options?.who || "admin", target: accountId });
    saveDb(db);
    return acct;
  }

  function removeAccount(accountId, options) {
    const db = loadDb();
    const idx = db.accounts.findIndex((a) => a.id === accountId);
    if (idx < 0) return false;
    const acct = db.accounts[idx];
    if (acct.role === "admin") throw new Error("Admin account cannot be removed.");
    db.accounts.splice(idx, 1);
    db.audit.push({ at: nowIso(), action: "account_removed", who: options?.who || "admin", target: accountId });
    saveDb(db);
    return true;
  }

  function listAnnouncements() {
    const db = loadDb();
    return db.announcements.slice().sort((a, b) => (b.id || 0) - (a.id || 0));
  }

  function saveAnnouncement(announcement, options) {
    const db = loadDb();
    const existingId = Number(announcement?.id || 0);
    if (existingId > 0) {
      const idx = db.announcements.findIndex((a) => a.id === existingId);
      if (idx >= 0) {
        db.announcements[idx] = { ...db.announcements[idx], ...announcement, updatedAt: nowIso() };
      }
    } else {
      const newId = db.announcements.length > 0 ? Math.max(...db.announcements.map((a) => a.id || 0)) + 1 : 1;
      db.announcements.push({ ...announcement, id: newId, createdAt: nowIso(), updatedAt: nowIso() });
    }
    db.audit.push({ at: nowIso(), action: "announcement_saved", who: options?.who || "admin" });
    saveDb(db);
  }

  function deleteAnnouncement(id, options) {
    const db = loadDb();
    db.announcements = db.announcements.filter((a) => a.id !== id);
    db.audit.push({ at: nowIso(), action: "announcement_deleted", who: options?.who || "admin" });
    saveDb(db);
  }

  function downloadJson(filename, dataObj) {
    const blob = new Blob([JSON.stringify(dataObj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportDb() {
    const db = loadDb();
    downloadJson("bis_data.json", db);
  }

  async function importDbFromFile(file) {
    const text = await file.text();
    const incoming = safeJsonParse(text, null);
    if (!incoming || typeof incoming !== "object") throw new Error("Invalid file.");
    if (!Array.isArray(incoming.accounts) || !Array.isArray(incoming.announcements)) {
      throw new Error("Invalid BIS data file.");
    }
    // Minimal validation: ensure no missing fields
    incoming.version = 1;
    if (!incoming.createdAt) incoming.createdAt = nowIso();
    incoming.updatedAt = nowIso();
    if (!Array.isArray(incoming.audit)) incoming.audit = [];
    saveDb(incoming);
    return true;
  }

  ensureSeeded();

  window.BIS = {
    DB_KEY,
    SESSION_KEY,
    ensureSeeded,
    db: { load: loadDb, save: saveDb, export: exportDb, importFromFile: importDbFromFile },
    auth: { verifyLogin, setSession, clearSession, getSession, getCurrentAccount, requireAuth },
    accounts: { list: listAccounts, create: createAccount, update: updateAccountProfile, remove: removeAccount, setPassword: setAccountPassword, validatePassword },
    announcements: { list: listAnnouncements, save: saveAnnouncement, delete: deleteAnnouncement },
    util: { normalizeUsername },
  };
})();

