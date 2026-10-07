/* Administrator settings: school details, map file and social links. */
(function () {
  "use strict";

  var admin = BIS.auth.requireAuth({ role: "admin" });
  if (!admin) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var FIELDS = ["schoolName", "shortName", "tagline", "address", "phone", "email", "mapFile", "mapQuery"];
  var SOCIAL = ["facebook", "telegram", "youtube", "tiktok"];
  var $ = function (id) { return document.getElementById(id); };

  function fill() {
    var s = BIS.settings.get();
    FIELDS.forEach(function (key) { $(key).value = s[key] || ""; });
    SOCIAL.forEach(function (key) { $(key).value = (s.social && s.social[key]) || ""; });
    $("mapPreview").src = s.mapFile || "map.png";
  }

  $("mapFile").addEventListener("change", function () {
    $("mapPreview").src = this.value.trim() || "map.png";
  });

  $("settingsForm").addEventListener("submit", function (event) {
    event.preventDefault();
    var patch = { social: {} };
    FIELDS.forEach(function (key) { patch[key] = $(key).value.trim(); });
    SOCIAL.forEach(function (key) { patch.social[key] = $(key).value.trim(); });
    try {
      BIS.settings.save(patch, { who: admin.id });
      UI.toast("Settings saved.", "ok");
      fill();
      setTimeout(function () { window.location.reload(); }, 800);
    } catch (err) {
      UI.toast(err.message || "Could not save the settings.", "err");
    }
  });

  $("resetBtn").addEventListener("click", function () {
    fill();
    UI.toast("Restored the last saved values.");
  });

  $("wipeBtn").addEventListener("click", function () {
    if (!UI.confirm("Erase ALL school data in this browser?\n\nAccounts, announcements, grades, timetables and attendance will be permanently removed.")) return;
    if (!UI.confirm("This cannot be undone. Erase everything now?")) return;
    BIS.db.reset();
    window.location.href = "login.html";
  });

  fill();
})();
