/* BIS core store: accounts, auth, sessions, announcements, timetable, attendance.
   Static front-end only. Passwords are PBKDF2-SHA256 hashed with a per-user salt
   and sessions are token based, but real security requires a server-side backend. */
(function () {
  "use strict";

  var DB_KEY = "bis_db_v3";
  var LEGACY_KEYS = ["bis_db_v2"];
  var SESSION_KEY = "bis_session_v2";
  var SCHEMA_VERSION = 3;
  var PBKDF2_ITERATIONS = 310000;
  var MAX_AUDIT = 400;
  var SESSION_TTL_MIN = 240;
  var IDLE_TIMEOUT_MIN = 30;
  var LOCKOUT_THRESHOLD = 5;
  var LOCKOUT_WINDOW_MIN = 15;
  var LOCKOUT_MIN = 15;
  var ROLES = ["admin", "teacher", "student"];
  var WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"];

  function nowIso() {
    return new Date().toISOString();
  }

  function minutesFromNow(min) {
    return new Date(Date.now() + min * 60000).toISOString();
  }

  function isFuture(iso) {
    return Boolean(iso) && new Date(iso).getTime() > Date.now();
  }

  function safeJsonParse(str, fallback) {
    try {
      var parsed = JSON.parse(str);
      return parsed && typeof parsed === "object" ? parsed : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function bytesToB64(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomHex(byteLength) {
    var bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("");
  }

  function timingSafeEqual(a, b) {
    var s1 = String(a || "");
    var s2 = String(b || "");
    var len = Math.max(s1.length, s2.length);
    var diff = s1.length === s2.length ? 0 : 1;
    for (var i = 0; i < len; i++) {
      diff |= (s1.charCodeAt(i) || 0) ^ (s2.charCodeAt(i) || 0);
    }
    return diff === 0;
  }

  function subtle() {
    return typeof crypto !== "undefined" && crypto.subtle ? crypto.subtle : null;
  }

  async function hashPassword(password, saltB64, iterations) {
    var rounds = iterations || PBKDF2_ITERATIONS;
    if (!subtle()) {
      throw new Error(
        "This browser cannot hash passwords securely (Web Crypto is unavailable). Open the system over https:// or http://localhost instead of a plain file:// page."
      );
    }
    var enc = new TextEncoder();
    var keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: b64ToBytes(saltB64), iterations: rounds, hash: "SHA-256" }, keyMaterial, 256);
    return bytesToB64(new Uint8Array(bits));
  }

  function newSalt() {
    return bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
  }

  function normalizeUsername(value) {
    return String(value == null ? "" : value)
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "");
  }

  function slugify(value) {
    return normalizeUsername(value).replace(/[^a-z0-9._-]/g, "");
  }

  function gradeKey(grade, section) {
    var g = String(grade == null ? "" : grade).trim().toUpperCase();
    var s = String(section == null ? "" : section).trim().toUpperCase();
    if (!g) return "";
    if (s && g.indexOf(s) < 0) g += s;
    return g.replace(/\s+/g, "");
  }

  function gradeKeyFromProfile(profile) {
    return gradeKey(profile && profile.grade, profile && profile.section);
  }

  function sanitizeText(value, maxLen) {
    var text = String(value == null ? "" : value)
      .replace(/[\u0000-\u001F\u007F]/g, "")
      .replace(/\s+/g, " ")
      .trim();
    return maxLen ? text.slice(0, maxLen) : text;
  }

  function sanitizeMultiline(value, maxLen) {
    var text = String(value == null ? "" : value)
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
      .replace(/\r\n?/g, "\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
    return maxLen ? text.slice(0, maxLen) : text;
  }

  function randomIndex(max) {
    var limit = Math.floor(4294967296 / max) * max;
    var buf = new Uint32Array(1);
    do {
      crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function randomPassword() {
    var sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "@#$%&*+?"];
    var all = sets.join("");
    var chars = sets.map(function (set) {
      return set[randomIndex(set.length)];
    });
    for (var i = 0; i < 8; i++) chars.push(all[randomIndex(all.length)]);
    for (var j = chars.length - 1; j > 0; j--) {
      var k = randomIndex(j + 1);
      var tmp = chars[j];
      chars[j] = chars[k];
      chars[k] = tmp;
    }
    return chars.join("");
  }

  function passwordProblems(pw) {
    var p = String(pw || "");
    var problems = [];
    if (p.length < 8) problems.push("at least 8 characters");
    if (p.length < 12) problems.push("12 or more characters is safer");
    if (!/[a-z]/.test(p)) problems.push("a lowercase letter");
    if (!/[A-Z]/.test(p)) problems.push("an uppercase letter");
    if (!/[0-9]/.test(p)) problems.push("a number");
    if (!/[^A-Za-z0-9]/.test(p)) problems.push("a symbol");
    if (/(.)\1{3,}/.test(p)) problems.push("no repeated characters like aaaa");
    if (/^(password|admin|school|bis|1234|qwerty|letmein)/i.test(p)) problems.push("not a common word");
    return problems;
  }

  function passwordStrength(pw) {
    var p = String(pw || "");
    if (!p) return { score: 0, label: "Empty", ok: false };
    var score = 0;
    if (p.length >= 8) score++;
    if (p.length >= 12) score++;
    if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    var labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"];
    return { score: score, label: labels[score], ok: passwordProblems(p).length === 0 };
  }

  function nextId(role) {
    var prefix = role === "student" ? "STD" : role === "teacher" ? "TCH" : "ADM";
    return prefix + "-" + new Date().getFullYear() + "-" + randomHex(4).toUpperCase();
  }

  function defaultSettings() {
    return {
      schoolName: "Bonafide International School",
      shortName: "BIS",
      tagline: "Center of Quality Education",
      address: "3FJM+9VC, Hawassa, Sidama, Ethiopia",
      phone: "+251 46 212 5487",
      email: "bonafideschool@gmail.com",
      mapFile: "map.png",
      mapQuery: "Bonafide School, Hawassa, Ethiopia",
      social: {
        facebook: "https://www.facebook.com/profile.php?id=61557851047466",
        telegram: "https://t.me/bonafideschools",
        youtube: "https://youtube.com/@Bonafideschool-yw4hv?si=T4wesJq5-NnC24f6"
      }
    };
  }

  function emptyDb() {
    return {
      version: SCHEMA_VERSION,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      settings: defaultSettings(),
      accounts: [],
      announcements: [],
      timetable: {},
      attendance: {},
      audit: []
    };
  }

  function normalizeAccount(raw) {
    var account = raw && typeof raw === "object" ? raw : {};
    var role = ROLES.indexOf(account.role) >= 0 ? account.role : "student";
    var profile = account.profile && typeof account.profile === "object" ? account.profile : {};
    var security = account.security && typeof account.security === "object" ? account.security : {};
    var password = account.password && typeof account.password === "object" ? account.password : {};
    return {
      id: String(account.id || nextId(role)),
      role: role,
      username: normalizeUsername(account.username) || normalizeUsername(account.displayName),
      displayName: sanitizeText(account.displayName || account.name || account.username, 80) || "Unnamed",
      email: sanitizeText(account.email, 120),
      phone: sanitizeText(account.phone, 40),
      status: account.status === "Inactive" || account.status === "Suspended" ? account.status : "Active",
      photoDataUrl: typeof account.photoDataUrl === "string" ? account.photoDataUrl : "",
      profile: {
        grade: sanitizeText(profile.grade, 20),
        section: sanitizeText(profile.section, 20),
        age: profile.age == null ? "" : sanitizeText(profile.age, 5),
        sex: sanitizeText(profile.sex, 10),
        teacherId: sanitizeText(profile.teacherId, 40),
        teacherName: sanitizeText(profile.teacherName, 80),
        subject: sanitizeText(profile.subject, 60),
        teachingGrades: sanitizeText(profile.teachingGrades, 120),
        admissionYear: profile.admissionYear == null ? "" : sanitizeText(profile.admissionYear, 10)
      },
      grades: normalizeGrades(account.grades),
      security: {
        mustChangePassword: Boolean(security.mustChangePassword),
        failedAttempts: Number(security.failedAttempts) || 0,
        firstFailedAt: security.firstFailedAt || null,
        lockedUntil: security.lockedUntil || null,
        lastLoginAt: security.lastLoginAt || null,
        lastFailedAt: security.lastFailedAt || null,
        passwordChangedAt: security.passwordChangedAt || null
      },
      password: {
        algo: password.algo || "PBKDF2-SHA256",
        iterations: Number(password.iterations) || PBKDF2_ITERATIONS,
        saltB64: password.saltB64 || "",
        hashB64: password.hashB64 || "",
        updatedAt: password.updatedAt || null
      },
      createdAt: account.createdAt || nowIso(),
      updatedAt: account.updatedAt || nowIso(),
      createdBy: sanitizeText(account.createdBy, 40)
    };
  }

  function normalizeGrades(raw) {
    var out = {};
    if (!raw || typeof raw !== "object") return out;
    Object.keys(raw).forEach(function (subject) {
      var value = raw[subject];
      if (value == null || value === "") return;
      var num = Number(value);
      if (!Number.isFinite(num)) return;
      out[sanitizeText(subject, 40)] = Math.max(0, Math.min(100, Math.round(num * 10) / 10));
    });
    return out;
  }

  function migrate(raw) {
    var db = emptyDb();
    if (!raw || typeof raw !== "object") return db;
    db.settings = Object.assign(defaultSettings(), raw.settings || {});
    db.accounts = (Array.isArray(raw.accounts) ? raw.accounts : []).map(normalizeAccount);
    db.announcements = (Array.isArray(raw.announcements) ? raw.announcements : []).map(function (a) {
      return {
        id: Number(a.id) || Date.now(),
        title: sanitizeText(a.title, 140),
        body: sanitizeText(a.body, 4000),
        author: sanitizeText(a.author, 80),
        audience: ROLES.concat(["all"]).indexOf(a.audience) >= 0 ? a.audience : "all",
        pinned: Boolean(a.pinned),
        createdAt: a.createdAt || nowIso(),
        updatedAt: a.updatedAt || nowIso(),
        date: a.date || ""
      };
    });
    db.timetable = raw.timetable && typeof raw.timetable === "object" ? raw.timetable : {};
    db.attendance = raw.attendance && typeof raw.attendance === "object" ? raw.attendance : {};
    db.audit = (Array.isArray(raw.audit) ? raw.audit : []).slice(-MAX_AUDIT);
    db.createdAt = raw.createdAt || db.createdAt;
    db.updatedAt = raw.updatedAt || db.updatedAt;
    db.version = SCHEMA_VERSION;
    return db;
  }

  function loadDb() {
    var raw = safeJsonParse(localStorage.getItem(DB_KEY), null);
    if (raw) return migrate(raw);
    for (var i = 0; i < LEGACY_KEYS.length; i++) {
      var legacy = safeJsonParse(localStorage.getItem(LEGACY_KEYS[i]), null);
      if (legacy) {
        var migrated = migrate(legacy);
        saveDb(migrated);
        LEGACY_KEYS.forEach(function (k) {
          localStorage.removeItem(k);
        });
        return migrated;
      }
    }
    return emptyDb();
  }

  var writeTimer = null;
  function saveDb(db) {
    db.updatedAt = nowIso();
    if (db.audit.length > MAX_AUDIT) db.audit = db.audit.slice(-MAX_AUDIT);
    localStorage.setItem(DB_KEY, JSON.stringify(db));
    return db;
  }

  function persist(db) {
    try {
      return saveDb(db);
    } catch (e) {
      console.error("BIS: could not save data", e);
      throw new Error("Browser storage is full. Export a backup and remove large photos.");
    }
  }

  function addAudit(db, action, actorId, target, extra) {
    db.audit.push({
      at: nowIso(),
      action: action,
      who: actorId || "system",
      target: target || "",
      detail: extra || ""
    });
  }

  function findAccount(db, idOrUsername) {
    var key = String(idOrUsername || "").trim();
    var uname = normalizeUsername(key);
    return (
      db.accounts.find(function (a) {
        return a.id === key;
      }) ||
      db.accounts.find(function (a) {
        return a.username === uname;
      }) ||
      null
    );
  }

  function isFirstRun() {
    return loadDb().accounts.length === 0;
  }

  function countActiveAdmins(db) {
    var data = db || loadDb();
    return data.accounts.filter(function (a) {
      return a.role === "admin" && a.status === "Active";
    }).length;
  }

  function auditList(limit) {
    return loadDb()
      .audit.slice()
      .reverse()
      .slice(0, limit || 60);
  }

  function sessionRecord() {
    var s = safeJsonParse(sessionStorage.getItem(SESSION_KEY), null);
    if (!s || !s.token || !s.userId) return null;
    return s;
  }

  function readSession() {
    var s = sessionRecord();
    if (!s) return null;
    if (s.expiresAt && new Date(s.expiresAt).getTime() <= Date.now()) {
      clearSession();
      return null;
    }
    return s;
  }

  function startSession(account) {
    var token = randomHex(32);
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        token: token,
        userId: account.id,
        username: account.username,
        role: account.role,
        fingerprint: account.password.hashB64,
        createdAt: nowIso(),
        lastSeenAt: nowIso(),
        expiresAt: minutesFromNow(SESSION_TTL_MIN)
      })
    );
    return sessionRecord();
  }

  function touchSession() {
    var s = readSession();
    if (!s) return null;
    if (Date.now() - new Date(s.lastSeenAt).getTime() > IDLE_TIMEOUT_MIN * 60000) {
      clearSession();
      return null;
    }
    s.lastSeenAt = nowIso();
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
    return s;
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  function getCurrentAccount() {
    var s = touchSession();
    if (!s) return null;
    var db = loadDb();
    var acct = db.accounts.find(function (a) {
      return a.id === s.userId;
    });
    if (!acct || acct.status !== "Active") {
      clearSession();
      return null;
    }
    if (acct.password.hashB64 && s.fingerprint && acct.password.hashB64 !== s.fingerprint) {
      clearSession();
      return null;
    }
    if (acct.security.mustChangePassword) return Object.assign({}, acct);
    return acct;
  }

  function requireAuth(options) {
    var opts = options || {};
    var acct = getCurrentAccount();
    if (!acct) {
      if (!opts.soft) {
        clearSession();
        window.location.replace(opts.redirectTo || "login.html");
      }
      return null;
    }
    if (opts.role) {
      var allowed = Array.isArray(opts.role) ? opts.role : [opts.role];
      if (allowed.indexOf(acct.role) < 0) {
        if (!opts.soft) window.location.replace(opts.redirectTo || "login.html");
        return null;
      }
    }
    return acct;
  }

  function requirePasswordChange() {
    if (!requireAuth({})) return false;
    var s = readSession();
    if (!s) return false;
    var acct = getCurrentAccount();
    if (acct && acct.security.mustChangePassword) {
      window.location.replace("change_password.html?required=1");
      return false;
    }
    return true;
  }

  function recordFailure(db, account) {
    var sec = account.security;
    var windowStart = isFuture(sec.lockedUntil) ? sec.lockedUntil : sec.firstFailedAt;
    if (!sec.firstFailedAt || !windowStart || new Date(windowStart).getTime() < Date.now() - LOCKOUT_WINDOW_MIN * 60000) {
      sec.firstFailedAt = nowIso();
      sec.failedAttempts = 0;
    }
    sec.failedAttempts += 1;
    sec.lastFailedAt = nowIso();
    if (sec.failedAttempts >= LOCKOUT_THRESHOLD) {
      sec.lockedUntil = minutesFromNow(LOCKOUT_MIN);
      sec.failedAttempts = 0;
      addAudit(db, "account_locked", "system", account.id, "too many failed logins");
    }
  }

  async function verifyLogin(username, password) {
    await ensureReady();
    var db = loadDb();
    var uname = normalizeUsername(username);
    var acct = db.accounts.find(function (a) {
      return a.username === uname;
    });

    if (!acct) {
      await hashPassword(String(password || ""), newSalt(), 1000);
      return { ok: false, reason: "Incorrect username or password." };
    }
    if (acct.status !== "Active") {
      return { ok: false, reason: "This account is " + acct.status.toLowerCase() + ". Contact an administrator." };
    }
    if (isFuture(acct.security.lockedUntil)) {
      var mins = Math.max(1, Math.ceil((new Date(acct.security.lockedUntil).getTime() - Date.now()) / 60000));
      return { ok: false, reason: "Account locked after too many failed attempts. Try again in " + mins + " minute(s)." };
    }
    if (!acct.password.hashB64 || !acct.password.saltB64) {
      return { ok: false, reason: "This account has no password set. Ask an administrator to reset it." };
    }

    var hash = await hashPassword(password, acct.password.saltB64, acct.password.iterations);
    if (!timingSafeEqual(hash, acct.password.hashB64)) {
      recordFailure(db, acct);
      addAudit(db, "login_failed", "system", acct.id, uname);
      saveDb(db);
      var left = Math.max(0, LOCKOUT_THRESHOLD - acct.security.failedAttempts);
      return {
        ok: false,
        reason: "Incorrect username or password." + (left > 0 && left <= 2 ? " " + left + " attempt(s) left before lockout." : "")
      };
    }

    acct.security.failedAttempts = 0;
    acct.security.firstFailedAt = null;
    acct.security.lockedUntil = null;
    acct.security.lastLoginAt = nowIso();
    addAudit(db, "login_ok", acct.id, acct.id, uname);
    saveDb(db);
    return { ok: true, account: acct, mustChangePassword: Boolean(acct.security.mustChangePassword) };
  }

  async function setPassword(accountId, newPassword, options) {
    var opts = options || {};
    var db = loadDb();
    var acct = findAccount(db, accountId);
    if (!acct) throw new Error("Account not found.");
    var problems = passwordProblems(newPassword);
    if (opts.exact !== false && problems.length) {
      throw new Error("Password needs " + problems.join(", ") + ".");
    }
    if (timingSafeEqual(newPassword, opts.currentPassword || "\u0000")) {
      throw new Error("New password must be different from the current one.");
    }
    var salt = newSalt();
    acct.password = {
      algo: "PBKDF2-SHA256",
      iterations: PBKDF2_ITERATIONS,
      saltB64: salt,
      hashB64: await hashPassword(newPassword, salt),
      updatedAt: nowIso()
    };
    acct.security.mustChangePassword = Boolean(opts.mustChangePassword);
    acct.security.passwordChangedAt = nowIso();
    acct.updatedAt = nowIso();
    addAudit(db, opts.mustChangePassword ? "password_reset" : "password_changed", opts.who || acct.id, acct.id, opts.reason || "");
    persist(db);
    if (opts.who) {
      var live = readSession();
      if (live && live.userId === acct.id) {
        live.fingerprint = acct.password.hashB64;
        live.createdAt = nowIso();
        live.lastSeenAt = nowIso();
        live.expiresAt = minutesFromNow(SESSION_TTL_MIN);
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(live));
      }
    }
    return acct;
  }

  function accountDefaults(role, username) {
    return normalizeAccount({ role: role, username: username, status: "Active" });
  }

  async function createAccount(payload, options) {
    var opts = options || {};
    var db = loadDb();
    var role = payload && payload.role;
    if (ROLES.indexOf(role) < 0) throw new Error("Choose a valid role.");
    if (role === "admin" && opts.who !== "bootstrap" && !isAdminActor(opts.who)) {
      throw new Error("Only administrators can create administrator accounts.");
    }

    var displayName = sanitizeText(payload.displayName, 80);
    if (!displayName) throw new Error("Full name is required.");
    var username = normalizeUsername(payload.username || slugify(displayName));
    var problems = usernameProblems(username);
    if (problems.length) throw new Error("Username " + problems.join(" ") + ".");
    if (db.accounts.some(function (a) { return a.username === username; })) {
      throw new Error('The username "' + username + '" is already taken.');
    }
    if (role === "student" && !sanitizeText(payload.profile && payload.profile.grade, 20)) {
      throw new Error("Students need a grade.");
    }

    var account = accountDefaults(role, username);
    account.id = nextId(role);
    account.displayName = displayName;
    account.email = sanitizeText(payload.email, 120);
    account.phone = sanitizeText(payload.phone, 40);
    account.status = opts.status === "Inactive" ? "Inactive" : "Active";
    account.photoDataUrl = typeof payload.photoDataUrl === "string" ? payload.photoDataUrl : "";
    account.profile = Object.assign(account.profile, {
      grade: sanitizeText(payload.profile && payload.profile.grade, 20),
      section: sanitizeText(payload.profile && payload.profile.section, 20),
      age: sanitizeText(payload.profile && payload.profile.age, 5),
      sex: sanitizeText(payload.profile && payload.profile.sex, 10),
      subject: sanitizeText(payload.profile && payload.profile.subject, 60),
      teachingGrades: sanitizeText(payload.profile && payload.profile.teachingGrades, 120),
      admissionYear: sanitizeText(payload.profile && payload.profile.admissionYear, 10)
    });
    if (role === "student") {
      var teacher = findAccount(db, sanitizeText(payload.profile && payload.profile.teacherId, 40));
      if (!teacher && sanitizeText(payload.profile && payload.profile.teacherName, 80)) {
        teacher = db.accounts.find(function (a) {
          return a.role === "teacher" && a.displayName === payload.profile.teacherName;
        });
      }
      if (teacher) {
        account.profile.teacherId = teacher.id;
        account.profile.teacherName = teacher.displayName;
      } else {
        account.profile.teacherName = sanitizeText(payload.profile && payload.profile.teacherName, 80);
      }
    }

    var tempPassword = payload.password || randomPassword();
    var pwProblems = passwordProblems(tempPassword);
    if (pwProblems.length) throw new Error("Password needs " + pwProblems.join(", ") + ".");
    if (payload.username && !slugify(payload.username)) throw new Error("Username must use letters or numbers.");

    var salt = newSalt();
    account.password = {
      algo: "PBKDF2-SHA256",
      iterations: PBKDF2_ITERATIONS,
      saltB64: salt,
      hashB64: await hashPassword(tempPassword, salt),
      updatedAt: nowIso()
    };
    account.security.mustChangePassword = true;
    account.security.passwordChangedAt = nowIso();
    account.createdBy = opts.who || "system";

    db.accounts.push(account);
    addAudit(db, "account_created", opts.who || "system", account.id, role + ":" + username);
    persist(db);
    return { account: account, tempPassword: tempPassword };
  }

  function usernameProblems(username) {
    var problems = [];
    if (!username) return ["is required"];
    if (username.length < 3) problems.push("is too short (min 3 characters)");
    if (username.length > 32) problems.push("is too long (max 32 characters)");
    if (!/^[a-z0-9._-]+$/.test(username)) problems.push("may only use letters, numbers, dot, dash and underscore");
    return problems;
  }

  function isAdminActor(actorId) {
    var db = loadDb();
    var actor = findAccount(db, actorId);
    return Boolean(actor && actor.role === "admin" && actor.status === "Active");
  }

  var ADMIN_WRITABLE_FIELDS = ["displayName", "email", "phone", "photoDataUrl", "username", "role", "status", "profile", "grades"];
  var SELF_WRITABLE_FIELDS = ["displayName", "email", "phone", "photoDataUrl"];
  var TEACHER_WRITABLE_FIELDS = ["grades"];

  function teacherOnlyGrades(patch) {
    var keys = Object.keys(patch || {});
    return keys.length > 0 && keys.every(function (k) { return TEACHER_WRITABLE_FIELDS.indexOf(k) >= 0; });
  }

  function teachesStudent(db, teacherId, profile) {
    var teacher = findAccount(db, teacherId);
    if (!teacher || teacher.role !== "teacher" || teacher.status !== "Active") return false;
    var mine = String(teacher.profile.teachingGrades || "")
      .split(",")
      .map(function (g) { return gradeKey(g); })
      .filter(Boolean);
    return mine.indexOf(gradeKeyFromProfile(profile)) >= 0;
  }

  function updateAccount(accountId, patch, options) {
    var opts = options || {};
    var db = loadDb();
    var acct = findAccount(db, accountId);
    if (!acct) throw new Error("Account not found.");
    var isAdmin = isAdminActor(opts.who);
    var isSelf = (opts.who || "") === acct.id;
    if (!isAdmin && !isSelf) {
      var teacherMayGrade = Boolean(opts.teacherId) && acct.role === "student" && teachesStudent(db, opts.teacherId, acct.profile);
      if (!teacherOnlyGrades(patch) || !teacherMayGrade) {
        throw new Error("You cannot edit this account.");
      }
    }
    var writableByActor = isAdmin ? ADMIN_WRITABLE_FIELDS : isSelf ? SELF_WRITABLE_FIELDS : TEACHER_WRITABLE_FIELDS;
    Object.keys(patch || {}).forEach(function (key) {
      if (writableByActor.indexOf(key) < 0) {
        throw new Error('You are not allowed to change "' + key + '".');
      }
    });

    if (patch.displayName != null) {
      var name = sanitizeText(patch.displayName, 80);
      if (!name) throw new Error("Full name is required.");
      acct.displayName = name;
    }
    if (patch.email != null) acct.email = sanitizeText(patch.email, 120);
    if (patch.phone != null) acct.phone = sanitizeText(patch.phone, 40);
    if (patch.photoDataUrl != null) acct.photoDataUrl = String(patch.photoDataUrl);
    if (patch.username != null && isAdmin) {
      var next = normalizeUsername(patch.username);
      var problems = usernameProblems(next);
      if (problems.length) throw new Error("Username " + problems.join(" ") + ".");
      if (db.accounts.some(function (a) { return a.username === next && a.id !== acct.id; })) {
        throw new Error('The username "' + next + '" is already taken.');
      }
      acct.username = next;
    }
    if (patch.role != null && isAdmin) {
      if (ROLES.indexOf(patch.role) < 0) throw new Error("Choose a valid role.");
      if (acct.role === "admin" && patch.role !== "admin" && countActiveAdmins(db) <= 1) {
        throw new Error("At least one active administrator must remain.");
      }
      acct.role = patch.role;
    }
    if (patch.status != null && isAdmin) {
      if (["Active", "Inactive", "Suspended"].indexOf(patch.status) < 0) throw new Error("Choose a valid status.");
      if (acct.role === "admin" && patch.status !== "Active" && countActiveAdmins(db) <= 1) {
        throw new Error("At least one active administrator must remain.");
      }
      acct.status = patch.status;
    }
    if (patch.profile != null) {
      Object.keys(patch.profile).forEach(function (key) {
        if (key === "teacherId") {
          var teacher = findAccount(db, patch.profile.teacherId);
          if (teacher && teacher.role === "teacher") {
            acct.profile.teacherId = teacher.id;
            acct.profile.teacherName = teacher.displayName;
          }
          return;
        }
        if (key === "teacherName" && !isAdmin) return;
        if (key in acct.profile) acct.profile[key] = sanitizeText(patch.profile[key], 120);
      });
    }
    if (patch.grades != null) acct.grades = normalizeGrades(patch.grades);
    acct.updatedAt = nowIso();
    addAudit(db, "account_updated", opts.who || acct.id, acct.id, Object.keys(patch || {}).join(","));
    persist(db);
    return acct;
  }

  function removeAccount(accountId, options) {
    var opts = options || {};
    var db = loadDb();
    var acct = findAccount(db, accountId);
    if (!acct) throw new Error("Account not found.");
    if (!isAdminActor(opts.who)) throw new Error("Only administrators can remove accounts.");
    if (acct.id === opts.who) throw new Error("You cannot remove your own account.");
    if (acct.role === "admin" && countActiveAdmins(db) <= 1) {
      throw new Error("At least one active administrator must remain.");
    }
    var idx = db.accounts.indexOf(acct);
    db.accounts.splice(idx, 1);
    Object.keys(db.attendance).forEach(function (date) {
      delete db.attendance[date][acct.id];
    });
    addAudit(db, "account_removed", opts.who, acct.id, acct.username);
    persist(db);
    return true;
  }

  function unlockAccount(accountId, options) {
    var opts = options || {};
    var db = loadDb();
    var acct = findAccount(db, accountId);
    if (!acct) throw new Error("Account not found.");
    if (!isAdminActor(opts.who)) throw new Error("Only administrators can unlock accounts.");
    acct.security.lockedUntil = null;
    acct.security.failedAttempts = 0;
    acct.security.firstFailedAt = null;
    acct.updatedAt = nowIso();
    addAudit(db, "account_unlocked", opts.who, acct.id, acct.username);
    persist(db);
    return acct;
  }

  function listAccounts(filter) {
    var accounts = loadDb().accounts.slice();
    if (filter && filter.role) accounts = accounts.filter(function (a) { return a.role === filter.role; });
    return accounts.sort(function (a, b) {
      return a.displayName.localeCompare(b.displayName);
    });
  }

  function getAccount(id) {
    return loadDb().accounts.find(function (a) { return a.id === id; }) || null;
  }

  function listAnnouncements(audience) {
    var all = loadDb()
      .announcements.slice()
      .sort(function (a, b) {
        if (Boolean(b.pinned) !== Boolean(a.pinned)) return b.pinned ? 1 : -1;
        return new Date(b.createdAt) - new Date(a.createdAt);
      });
    if (!audience || audience === "all") return all;
    return all.filter(function (a) {
      return a.audience === audience || a.audience === "all";
    });
  }

  function saveAnnouncement(data, options) {
    var opts = options || {};
    if (!isAdminActor(opts.who)) throw new Error("Only administrators can publish announcements.");
    var db = loadDb();
    var title = sanitizeText(data.title, 140);
    var body = sanitizeMultiline(data.body, 4000);
    if (!title) throw new Error("Title is required.");
    if (!body) throw new Error("Content is required.");
    var audience = ROLES.concat(["all"]).indexOf(data.audience) >= 0 ? data.audience : "all";
    var existingId = Number(data.id) || 0;
    if (existingId) {
      var idx = db.announcements.findIndex(function (a) { return a.id === existingId; });
      if (idx < 0) throw new Error("Announcement not found.");
      db.announcements[idx] = Object.assign({}, db.announcements[idx], {
        title: title,
        body: body,
        audience: audience,
        pinned: Boolean(data.pinned),
        updatedAt: nowIso()
      });
      addAudit(db, "announcement_updated", opts.who, String(existingId), title);
    } else {
      var nextIdValue = db.announcements.reduce(function (max, a) { return Math.max(max, Number(a.id) || 0); }, 0) + 1;
      db.announcements.push({
        id: nextIdValue,
        title: title,
        body: body,
        audience: audience,
        pinned: Boolean(data.pinned),
        author: opts.authorName || "Administration",
        authorId: opts.who || "",
        createdAt: nowIso(),
        updatedAt: nowIso(),
        date: new Date().toLocaleDateString("en-GB", { year: "numeric", month: "short", day: "numeric" })
      });
      addAudit(db, "announcement_created", opts.who, String(nextIdValue), title);
    }
    persist(db);
    return true;
  }

  function deleteAnnouncement(id, options) {
    var opts = options || {};
    if (!isAdminActor(opts.who)) throw new Error("Only administrators can delete announcements.");
    var db = loadDb();
    var before = db.announcements.length;
    db.announcements = db.announcements.filter(function (a) { return a.id !== Number(id); });
    if (db.announcements.length === before) throw new Error("Announcement not found.");
    addAudit(db, "announcement_deleted", opts.who, String(id), "");
    persist(db);
    return true;
  }

  function getTimetable(grade) {
    var key = gradeKey(grade);
    var table = loadDb().timetable[key] || {};
    return WEEKDAYS.map(function (day) {
      return { day: day, periods: Array.isArray(table[day]) ? table[day] : [] };
    });
  }

  function setTimetableDay(grade, day, periods, options) {
    var opts = options || {};
    var key = gradeKey(grade);
    if (!key) throw new Error("Grade is required.");
    if (WEEKDAYS.indexOf(day) < 0) throw new Error("Unknown day.");
    if (!isAdminActor(opts.who) && !isAdminActor(opts.teacherId)) {
      var teacher = findAccount(loadDb(), opts.teacherId);
      if (!teacher || teacher.role !== "teacher") throw new Error("Not allowed.");
      var mine = teacher.profile.teachingGrades.split(",").map(function (g) { return gradeKey(g); });
      if (mine.indexOf(key) < 0) throw new Error("You are not assigned to grade " + key + ".");
    }
    var db = loadDb();
    db.timetable[key] = db.timetable[key] || {};
    db.timetable[key][day] = (Array.isArray(periods) ? periods : []).map(function (p) {
      return {
        start: sanitizeText(p.start, 10),
        end: sanitizeText(p.end, 10),
        subject: sanitizeText(p.subject, 60),
        room: sanitizeText(p.room, 20),
        teacherId: sanitizeText(p.teacherId, 40),
        teacherName: sanitizeText(p.teacherName, 80)
      };
    });
    addAudit(db, "timetable_updated", opts.teacherId || opts.who || "system", key, day);
    persist(db);
    return true;
  }

  function listAttendanceDates(limit) {
    return Object.keys(loadDb().attendance)
      .sort()
      .reverse()
      .slice(0, limit || 30);
  }

  function getAttendance(date, grade) {
    var db = loadDb();
    var rows = db.attendance[date] || {};
    return listAccounts({ role: "student" })
      .filter(function (s) {
        return !grade || gradeKeyFromProfile(s.profile) === gradeKey(grade);
      })
      .map(function (s) {
        return { student: s, status: rows[s.id] || "" };
      });
  }

  function saveAttendance(date, grade, records, options) {
    var opts = options || {};
    var db = loadDb();
    var key = gradeKey(grade);
    var teacher = findAccount(db, opts.teacherId);
    if (!teacher || teacher.role !== "teacher") throw new Error("Not allowed.");
    if (!isAdminActor(opts.who)) {
      var mine = teacher.profile.teachingGrades.split(",").map(function (g) { return gradeKey(g); });
      if (mine.indexOf(key) < 0) throw new Error("You are not assigned to grade " + key + ".");
    }
    var allowed = ["present", "absent", "late", "excused"];
    db.attendance[date] = db.attendance[date] || {};
    Object.keys(records).forEach(function (studentId) {
      var status = records[studentId];
      if (allowed.indexOf(status) < 0) delete db.attendance[date][studentId];
      else db.attendance[date][studentId] = status;
    });
    addAudit(db, "attendance_saved", teacher.id, key + " " + date, Object.keys(records).length + " record(s)");
    persist(db);
    return true;
  }

  function studentAttendanceRate(studentId) {
    var db = loadDb();
    var present = 0;
    var total = 0;
    Object.keys(db.attendance).forEach(function (date) {
      var status = db.attendance[date][studentId];
      if (!status) return;
      total += 1;
      if (status === "present" || status === "late") present += 1;
    });
    return { present: present, total: total, rate: total ? Math.round((present / total) * 100) : null };
  }

  function attendanceForStudent(studentId, limit) {
    var db = loadDb();
    return Object.keys(db.attendance)
      .sort()
      .reverse()
      .slice(0, limit || 20)
      .map(function (date) {
        return { date: date, status: db.attendance[date][studentId] || "" };
      })
      .filter(function (r) { return r.status; });
  }

  function gradeAverage(grades) {
    var values = Object.keys(grades || {}).map(function (k) { return Number(grades[k]); });
    if (!values.length) return null;
    var sum = values.reduce(function (a, b) { return a + b; }, 0);
    return Math.round((sum / values.length) * 10) / 10;
  }

  function gradeLetter(value) {
    if (value == null) return "-";
    if (value >= 90) return "A";
    if (value >= 80) return "B";
    if (value >= 70) return "C";
    if (value >= 60) return "D";
    return "F";
  }

  function getSettings() {
    return loadDb().settings;
  }

  function saveSettings(patch, options) {
    var opts = options || {};
    if (!isAdminActor(opts.who)) throw new Error("Only administrators can change school settings.");
    var db = loadDb();
    var s = db.settings;
    ["schoolName", "shortName", "tagline", "address", "phone", "email", "mapFile", "mapQuery"].forEach(function (key) {
      if (patch[key] != null) s[key] = sanitizeText(patch[key], 160);
    });
    if (patch.social) {
      ["facebook", "telegram", "youtube"].forEach(function (key) {
        var url = sanitizeText(patch.social[key], 300);
        if (url && !/^https:\/\//i.test(url)) throw new Error("Social links must start with https://");
        s.social[key] = url;
      });
    }
    addAudit(db, "settings_updated", opts.who, "", "");
    persist(db);
    return s;
  }

  function downloadJson(filename, dataObj) {
    var blob = new Blob([JSON.stringify(dataObj, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function exportBackup() {
    var db = loadDb();
    var stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    downloadJson("bis-backup-" + stamp + ".json", db);
    return true;
  }

  function exportCredentials() {
    var accounts = loadDb().accounts.map(function (a) {
      return {
        id: a.id,
        role: a.role,
        username: a.username,
        name: a.displayName,
        grade: a.profile.grade,
        section: a.profile.section,
        subject: a.profile.subject,
        status: a.status,
        lastLoginAt: a.security.lastLoginAt || "",
        createdAt: a.createdAt
      };
    });
    var columns = ["id", "role", "username", "name", "grade", "section", "subject", "status", "lastLoginAt", "createdAt"];
    function cell(value) {
      var text = String(value == null ? "" : value);
      return /[",\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    }
    var csv = [columns.join(",")].concat(
      accounts.map(function (row) { return columns.map(function (c) { return cell(row[c]); }).join(","); })
    ).join("\r\n");
    var blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "bis-accounts.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    return accounts.length;
  }

  async function importBackup(source) {
    var text = typeof source === "string" ? source : source && typeof source.text === "function" ? await source.text() : JSON.stringify(source);
    var incoming = safeJsonParse(text, null);
    if (!incoming || typeof incoming !== "object") throw new Error("That file is not valid JSON.");
    if (!Array.isArray(incoming.accounts)) throw new Error("Not a BIS backup file (no accounts list).");
    var db = migrate(incoming);
    if (!db.accounts.filter(function (a) { return a.role === "admin" && a.status === "Active"; }).length) {
      throw new Error("The backup contains no active administrator, so it was not imported.");
    }
    persist(db);
    clearSession();
    return true;
  }

  function resetEverything() {
    localStorage.removeItem(DB_KEY);
    LEGACY_KEYS.forEach(function (k) { localStorage.removeItem(k); });
    clearSession();
    return true;
  }

  async function bootstrapFirstAdmin(form, options) {
    var opts = options || {};
    var db = loadDb();
    if (db.accounts.length > 0) throw new Error("This system is already set up. Sign in instead.");
    var result = await createAccount(
      {
        role: "admin",
        displayName: form.displayName,
        username: form.username,
        email: form.email,
        phone: form.phone,
        password: form.password
      },
      { who: "bootstrap" }
    );
    db = loadDb();
    db.accounts[0].security.mustChangePassword = false;
    addAudit(db, "system_bootstrapped", result.account.id, result.account.id, "");
    persist(db);
    var demo = opts.withDemo === false ? [] : await createDemoData(result.account.id);
    return { account: result.account, tempPassword: result.tempPassword, demo: demo };
  }

  async function createDemoData(adminId) {
    var created = [];
    var samples = [
      { role: "teacher", displayName: "Daniel Bekele", profile: { subject: "Mathematics", teachingGrades: "10A,10B,11A" } },
      { role: "teacher", displayName: "Eleni Tesfaye", profile: { subject: "English Literature", teachingGrades: "10B,11A" } },
      { role: "student", displayName: "Abebe Kebede", profile: { grade: "10", section: "A", sex: "M" } },
      { role: "student", displayName: "Chala Dibaba", profile: { grade: "10", section: "B", sex: "M" } },
      { role: "student", displayName: "Fatuma Ali", profile: { grade: "11", section: "A", sex: "F" } }
    ];
    for (var i = 0; i < samples.length; i++) {
      var s = samples[i];
      try {
        var res = await createAccount(
          {
            role: s.role,
            displayName: s.displayName,
            username: slugify(s.displayName) + (s.role === "student" ? "." + s.profile.grade.toLowerCase() + s.profile.section.toLowerCase() : ""),
            profile: s.profile
          },
          { who: adminId }
        );
        created.push({ id: res.account.id, username: res.account.username, password: res.tempPassword });
      } catch (e) {
        console.warn("BIS: demo account skipped", s.displayName, e.message);
      }
    }
    return created;
  }

  var readyPromise = null;
  function ensureReady() {
    if (!readyPromise) readyPromise = Promise.resolve();
    return readyPromise;
  }

  window.BIS = {
    VERSION: SCHEMA_VERSION,
    DB_KEY: DB_KEY,
    SESSION_KEY: SESSION_KEY,
    ROLES: ROLES,
    WEEKDAYS: WEEKDAYS,
    isFirstRun: isFirstRun,
    bootstrapFirstAdmin: bootstrapFirstAdmin,
    createDemoData: createDemoData,
    auth: {
      verifyLogin: verifyLogin,
      startSession: startSession,
      endSession: clearSession,
      getSession: readSession,
      getCurrentAccount: getCurrentAccount,
      requireAuth: requireAuth,
      requirePasswordChange: requirePasswordChange
    },
    accounts: {
      list: listAccounts,
      get: getAccount,
      create: createAccount,
      update: updateAccount,
      remove: removeAccount,
      unlock: unlockAccount,
      setPassword: setPassword,
      passwordProblems: passwordProblems,
      passwordStrength: passwordStrength,
      randomPassword: randomPassword,
      usernameProblems: usernameProblems,
      slugify: slugify
    },
    announcements: { list: listAnnouncements, save: saveAnnouncement, delete: deleteAnnouncement },
    timetable: { get: getTimetable, setDay: setTimetableDay },
    attendance: {
      dates: listAttendanceDates,
      get: getAttendance,
      save: saveAttendance,
      rateFor: studentAttendanceRate,
      forStudent: attendanceForStudent
    },
    grades: { average: gradeAverage, letter: gradeLetter },
    util: {
      normalizeUsername: normalizeUsername,
      slugify: slugify,
      randomPassword: randomPassword,
      gradeKey: gradeKey,
      gradeKeyFromProfile: gradeKeyFromProfile
    },
    audit: { list: auditList },
    settings: { get: getSettings, save: saveSettings },
    db: { load: loadDb, exportBackup: exportBackup, exportCredentials: exportCredentials, importBackup: importBackup, reset: resetEverything }
  };
})();
