/* Administrator dashboard: live counts, audit trail and backup tools. */
(function () {
  "use strict";

  var acct = BIS.auth.requireAuth({ role: "admin" });
  if (!acct) return;
  if (!BIS.auth.requirePasswordChange()) return;

  function renderProfile() {
    var card = document.getElementById("profileCard");
    card.innerHTML = "";
    card.appendChild(UI.avatar(acct.displayName, acct.photoDataUrl));
    card.appendChild(UI.el("h3", { text: acct.displayName }));
    card.appendChild(UI.el("p", { class: "muted", text: "Administrator · " + acct.id }));
    card.appendChild(UI.el("p", { class: "small muted", text: "Last sign-in: " + UI.formatDateTime(acct.security.lastLoginAt) }));
    card.appendChild(UI.el("a", { class: "btn btn-sm", href: "profile.html", text: "My profile" }));
  }

  function renderStats() {
    var accounts = BIS.accounts.list();
    var students = accounts.filter(function (a) { return a.role === "student" && a.status === "Active"; });
    var teachers = accounts.filter(function (a) { return a.role === "teacher" && a.status === "Active"; });
    var admins = accounts.filter(function (a) { return a.role === "admin" && a.status === "Active"; });
    var locked = accounts.filter(function (a) { return a.security.lockedUntil && new Date(a.security.lockedUntil) > new Date(); });
    var grades = {};
    students.forEach(function (s) {
      var g = (s.profile.grade || "Unassigned").toUpperCase();
      grades[g] = (grades[g] || 0) + 1;
    });
    var classCount = Object.keys(grades).length;
    var avgList = students.map(function (s) { return BIS.grades.average(s.grades); }).filter(function (v) { return v != null; });
    var schoolAverage = avgList.length
      ? Math.round((avgList.reduce(function (a, b) { return a + b; }, 0) / avgList.length) * 10) / 10
      : null;

    var tiles = [
      { value: students.length, label: "Active students" },
      { value: teachers.length, label: "Active teachers" },
      { value: admins.length, label: "Administrators" },
      { value: classCount, label: "Grades with students" },
      { value: schoolAverage == null ? "—" : schoolAverage, label: "School average mark" },
      { value: locked.length, label: "Locked accounts" }
    ];

    var host = document.getElementById("stats");
    host.innerHTML = "";
    tiles.forEach(function (tile) {
      host.appendChild(
        UI.el("div", { class: "stat-card" }, [
          UI.el("div", { class: "stat-value", text: String(tile.value) }),
          UI.el("div", { class: "stat-label", text: tile.label })
        ])
      );
    });
  }

  function renderAudit() {
    var list = document.getElementById("auditList");
    var entries = BIS.audit.list(15);
    list.innerHTML = "";
    if (!entries.length) {
      list.appendChild(UI.el("li", { text: "No activity recorded yet." }));
      return;
    }
    var accounts = BIS.accounts.list();
    var names = {};
    accounts.forEach(function (a) { names[a.id] = a.displayName; });
    entries.forEach(function (entry) {
      var who = entry.who === "system" ? "System" : names[entry.who] || entry.who;
      list.appendChild(
        UI.el("li", {}, [
          UI.el("span", {}, [
            UI.el("strong", { text: entry.action.replace(/_/g, " ") }),
            UI.el("span", { class: "muted small", text: " by " + who + (entry.detail ? " · " + entry.detail : "") })
          ]),
          UI.el("span", { class: "muted small", text: UI.formatDateTime(entry.at) })
        ])
      );
    });
  }

  document.getElementById("exportBtn").addEventListener("click", function () {
    BIS.db.exportBackup();
    UI.toast("Backup downloaded.", "ok");
  });

  document.getElementById("importInput").addEventListener("change", async function (event) {
    var file = event.target.files && event.target.files[0];
    if (!file) return;
    if (!UI.confirm("Restoring a backup replaces all current accounts, announcements and timetables. Continue?")) {
      event.target.value = "";
      return;
    }
    try {
      await BIS.db.importBackup(file);
      UI.toast("Backup restored. Reloading…", "ok");
      setTimeout(function () { window.location.reload(); }, 900);
    } catch (err) {
      UI.toast(err.message || "That backup could not be restored.", "err");
      event.target.value = "";
    }
  });

  renderProfile();
  renderStats();
  renderAudit();
})();
