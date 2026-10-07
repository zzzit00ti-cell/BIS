/* Self-service profile editing for any signed-in role. */
(function () {
  "use strict";

  var acct = BIS.auth.requireAuth({});
  if (!acct) return;

  var card = document.getElementById("profileCard");
  card.innerHTML = "";
  card.appendChild(UI.avatar(acct.displayName, acct.photoDataUrl));
  card.appendChild(UI.el("h3", { text: acct.displayName }));
  card.appendChild(UI.el("p", { class: "muted", text: (acct.profile.subject ? acct.profile.subject + " teacher" : acct.role) }));
  card.appendChild(UI.el("p", { class: "small", text: "ID: " + acct.id }));
  if (acct.profile.grade) {
    card.appendChild(UI.el("p", { class: "small muted", text: "Grade " + acct.profile.grade + (acct.profile.section ? " · Section " + acct.profile.section : "") }));
  }
  card.appendChild(UI.statusBadge(acct.status));
  if (acct.security.lastLoginAt) {
    card.appendChild(UI.el("p", { class: "small muted", text: "Last sign-in: " + UI.formatDateTime(acct.security.lastLoginAt) }));
  }

  document.getElementById("displayName").value = acct.displayName;
  document.getElementById("username").value = acct.username;
  document.getElementById("email").value = acct.email || "";
  document.getElementById("phone").value = acct.phone || "";
  document.getElementById("pwChanged").textContent = UI.formatDateTime(acct.security.passwordChangedAt || acct.password.updatedAt);

  document.getElementById("profileForm").addEventListener("submit", async function (event) {
    event.preventDefault();
    var photoInput = document.getElementById("photo");
    try {
      var photo = await UI.fileToDataUrl(photoInput.files && photoInput.files[0], 320);
      BIS.accounts.update(
        acct.id,
        {
          displayName: document.getElementById("displayName").value,
          email: document.getElementById("email").value,
          phone: document.getElementById("phone").value,
          photoDataUrl: photo || acct.photoDataUrl
        },
        { who: acct.id }
      );
      UI.toast("Profile saved.", "ok");
      setTimeout(function () {
        window.location.reload();
      }, 700);
    } catch (err) {
      UI.toast(err.message || "Could not save your profile.", "err");
    }
  });
})();
