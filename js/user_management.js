/* Administrator user directory: create admins/teachers/students, edit, reset passwords, unlock, remove. */
(function () {
  "use strict";

  var admin = BIS.auth.requireAuth({ role: "admin" });
  if (!admin) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var tbody = $("rows");
  var searchTerm = "";
  var roleFilter = "";

  function teacherOptions(select, selectedId) {
    var teachers = BIS.accounts.list({ role: "teacher" });
    select.innerHTML = "";
    select.appendChild(UI.el("option", { value: "", text: "Not assigned" }));
    teachers.forEach(function (t) {
      var opt = UI.el("option", { value: t.id, text: t.displayName + (t.profile.subject ? " (" + t.profile.subject + ")" : "") });
      if (t.id === selectedId) opt.selected = true;
      select.appendChild(opt);
    });
  }

  function detailText(acct) {
    if (acct.role === "student") {
      return "Grade " + (acct.profile.grade || "—") + (acct.profile.section ? " · " + acct.profile.section : "") +
        (acct.profile.teacherName ? " · " + acct.profile.teacherName : "");
    }
    if (acct.role === "teacher") {
      return (acct.profile.subject || "No subject") + (acct.profile.teachingGrades ? " · Grades " + acct.profile.teachingGrades : "");
    }
    return "Full system access";
  }

  function render() {
    var accounts = BIS.accounts.list();
    var needle = searchTerm.toLowerCase();
    var filtered = accounts.filter(function (a) {
      if (roleFilter && a.role !== roleFilter) return false;
      if (!needle) return true;
      return [a.id, a.username, a.displayName, a.profile.grade, a.profile.section, a.profile.subject, a.profile.teacherName, a.email]
        .join(" ")
        .toLowerCase()
        .indexOf(needle) >= 0;
    });

    $("count").textContent = filtered.length + " of " + accounts.length + " account(s)";
    tbody.innerHTML = "";

    if (!filtered.length) {
      var emptyRow = UI.el("tr", {}, [UI.el("td", { colspan: "7", class: "empty", text: "No accounts match your search." })]);
      tbody.appendChild(emptyRow);
      return;
    }

    filtered.forEach(function (a) {
      var locked = a.security.lockedUntil && new Date(a.security.lockedUntil) > new Date();
      var row = UI.el("tr");
      row.appendChild(UI.el("td", {}, [
        UI.el("div", { class: "row", style: "gap:10px;flex-wrap:nowrap" }, [
          UI.avatar(a.displayName, a.photoDataUrl, "sm"),
          UI.el("div", {}, [
            UI.el("strong", { text: a.displayName }),
            UI.el("div", { class: "muted small", text: a.id })
          ])
        ])
      ]));
      row.appendChild(UI.el("td", {}, [UI.el("code", { text: a.username })]));
      row.appendChild(UI.el("td", {}, [UI.roleBadge(a.role)]));
      row.appendChild(UI.el("td", { class: "small", text: detailText(a) }));
      row.appendChild(UI.el("td", {}, [UI.statusBadge(a.status), locked ? UI.el("div", { class: "small", style: "color:var(--danger)", text: "Locked" }) : ""]));
      row.appendChild(UI.el("td", { class: "small muted", text: UI.formatDateTime(a.security.lastLoginAt) }));

      var actions = UI.el("div", { class: "row-actions" });
      actions.appendChild(UI.el("button", { class: "btn btn-sm btn-ghost", style: "color:#0f172a", text: "Edit", onclick: function () { openEdit(a.id); } }));
      actions.appendChild(UI.el("button", { class: "btn btn-sm btn-amber", text: "Password", onclick: function () { resetPassword(a.id); } }));
      if (locked) {
        actions.appendChild(UI.el("button", { class: "btn btn-sm btn-green", text: "Unlock", onclick: function () { unlock(a.id); } }));
      }
      actions.appendChild(UI.el("button", { class: "btn btn-sm btn-danger", text: "Remove", onclick: function () { removeUser(a.id); } }));
      row.appendChild(UI.el("td", {}, [actions]));
      tbody.appendChild(row);
    });
  }

  function showCredentials(acct, password) {
    var content = UI.el("div");
    content.appendChild(
      UI.el("p", { class: "muted small", style: "margin-top:0", text: "Copy these details for the user. The password is shown only once." })
    );
    var box = UI.el("div", { class: "credential" });
    box.textContent = "Username: " + acct.username + "\nPassword: " + password;
    content.appendChild(box);
    UI.modal("Account created — " + acct.displayName, content, [
      {
        label: "Copy details",
        variant: "green",
        onClick: function (backdrop) {
          UI.copy(acct.username + "\t" + password)
            .then(function () { UI.toast("Copied to clipboard.", "ok"); })
            .catch(function () { UI.toast("Select the text and copy manually.", "err"); });
          backdrop.remove();
        }
      },
      { label: "Done" }
    ]);
  }

  function syncRoleFields() {
    var role = $("role").value;
    $("studentFields").classList.toggle("hidden", role !== "student");
    $("teacherFields").classList.toggle("hidden", role !== "teacher");
    $("teacherPickField").classList.toggle("hidden", role !== "student");
  }

  $("role").addEventListener("change", syncRoleFields);

  $("displayName").addEventListener("input", function () {
    var username = $("username");
    if (username.dataset.touched === "1") return;
    var slug = BIS.util.slugify(this.value);
    if ($("role").value === "student") {
      var grade = BIS.util.slugify($("grade").value);
      var section = BIS.util.slugify($("section").value);
      if (grade && section) slug += "." + grade + section;
    }
    username.value = slug;
    checkUsername(username.value);
  });

  function checkUsername(value) {
    var problems = BIS.accounts.usernameProblems(BIS.util.normalizeUsername(value));
    var hint = $("usernameHint");
    if (problems.length) {
      hint.textContent = "Username " + problems.join(" ") + ".";
      hint.style.color = "var(--danger)";
      return false;
    }
    var taken = BIS.accounts.list().some(function (a) { return a.username === BIS.util.normalizeUsername(value); });
    hint.textContent = taken ? "That username is already taken." : "Available.";
    hint.style.color = taken ? "var(--danger)" : "var(--success)";
    return !taken;
  }

  $("username").addEventListener("input", function () {
    this.dataset.touched = "1";
    checkUsername(this.value);
  });

  function refreshPassword() {
    $("password").value = BIS.accounts.randomPassword();
  }
  $("regenPw").addEventListener("click", refreshPassword);

  function openCreate() {
    $("editPanel").style.display = "none";
    $("createPanel").style.display = "block";
    $("createForm").reset();
    $("username").dataset.touched = "0";
    refreshPassword();
    teacherOptions($("teacherId"), "");
    syncRoleFields();
    checkUsername("");
    $("createPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    $("displayName").focus();
  }

  $("newUserBtn").addEventListener("click", openCreate);
  $("cancelCreate").addEventListener("click", function () { $("createPanel").style.display = "none"; });

  $("createForm").addEventListener("submit", async function (event) {
    event.preventDefault();
    var role = $("role").value;
    var payload = {
      role: role,
      displayName: $("displayName").value.trim(),
      username: $("username").value.trim(),
      email: $("email").value.trim(),
      password: $("password").value,
      profile: {
        grade: $("grade").value.trim(),
        section: $("section").value.trim(),
        age: $("age").value,
        sex: $("sex").value,
        subject: $("subject").value.trim(),
        teachingGrades: $("teachingGrades").value.trim(),
        teacherId: $("teacherId").value
      }
    };
    if (role !== "admin" && !UI.confirm("Create this " + role + " account now?")) return;

    $("createBtn").disabled = true;
    try {
      payload.photoDataUrl = await UI.fileToDataUrl($("photo").files && $("photo").files[0], 320);
      var result = await BIS.accounts.create(payload, { who: admin.id });
      $("createPanel").style.display = "none";
      render();
      showCredentials(result.account, result.tempPassword);
    } catch (err) {
      UI.toast(err.message || "Could not create that account.", "err");
    } finally {
      $("createBtn").disabled = false;
    }
  });

  function openEdit(id) {
    var a = BIS.accounts.get(id);
    if (!a) return;
    $("createPanel").style.display = "none";
    $("editPanel").style.display = "block";
    $("editId").value = a.id;
    $("editName").value = a.displayName;
    $("editUsername").value = a.username;
    $("editUsernameHint").textContent = "";
    $("editRole").value = a.role;
    $("editStatus").value = a.status;
    $("editEmail").value = a.email || "";
    $("editPhone").value = a.phone || "";
    $("editGrade").value = a.profile.grade || "";
    $("editSection").value = a.profile.section || "";
    $("editAge").value = a.profile.age || "";
    $("editSex").value = a.profile.sex || "";
    $("editSubject").value = a.profile.subject || "";
    $("editTeachingGrades").value = a.profile.teachingGrades || "";
    teacherOptions($("editTeacherId"), a.profile.teacherId);
    syncEditFields();
    $("editPanel").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function syncEditFields() {
    var role = $("editRole").value;
    $("editStudentFields").classList.toggle("hidden", role !== "student");
    $("editTeacherFields").classList.toggle("hidden", role !== "teacher");
  }
  $("editRole").addEventListener("change", syncEditFields);
  $("cancelEdit").addEventListener("click", function () { $("editPanel").style.display = "none"; });

  $("editForm").addEventListener("submit", function (event) {
    event.preventDefault();
    var role = $("editRole").value;
    try {
      BIS.accounts.update(
        $("editId").value,
        {
          displayName: $("editName").value,
          username: $("editUsername").value,
          role: role,
          status: $("editStatus").value,
          email: $("editEmail").value,
          phone: $("editPhone").value,
          profile: {
            grade: $("editGrade").value,
            section: $("editSection").value,
            age: $("editAge").value,
            sex: $("editSex").value,
            subject: $("editSubject").value,
            teachingGrades: $("editTeachingGrades").value,
            teacherId: $("editTeacherId").value
          }
        },
        { who: admin.id }
      );
      $("editPanel").style.display = "none";
      render();
      UI.toast("Account updated.", "ok");
    } catch (err) {
      UI.toast(err.message || "Could not update that account.", "err");
    }
  });

  function resetPassword(id) {
    var a = BIS.accounts.get(id);
    if (!a) return;
    var generated = BIS.accounts.randomPassword();
    var content = UI.el("div");
    content.appendChild(UI.el("p", { style: "margin-top:0", text: "Set a new password for " + a.displayName + ". They must change it after signing in." }));
    var input = UI.el("input", { type: "text", value: generated, style: "font-family:ui-monospace,Menlo,monospace" });
    content.appendChild(UI.el("label", { text: "New password" }));
    content.appendChild(input);
    var strength = UI.el("div");
    content.appendChild(strength);
    UI.passwordWidget(input, strength);
    content.appendChild(UI.el("div", { class: "row", style: "margin-top:10px" }, [
      UI.el("button", { class: "btn btn-sm btn-ghost", style: "color:#0f172a", text: "Regenerate", onclick: function () { input.value = BIS.accounts.randomPassword(); UI.passwordWidget(input, strength); } })
    ]));

    UI.modal("Reset password", content, [
      {
        label: "Set password",
        variant: "amber",
        onClick: async function (backdrop) {
          try {
            await BIS.accounts.setPassword(id, input.value, { who: admin.id, mustChangePassword: true, reason: "admin_reset" });
            backdrop.remove();
            render();
            UI.toast("Password reset for " + a.displayName + ".", "ok");
          } catch (err) {
            UI.toast(err.message || "Could not reset that password.", "err");
          }
        }
      },
      { label: "Cancel" }
    ]);
  }

  function unlock(id) {
    var a = BIS.accounts.get(id);
    if (!a) return;
    try {
      BIS.accounts.unlock(id, { who: admin.id });
      render();
      UI.toast(a.displayName + " unlocked.", "ok");
    } catch (err) {
      UI.toast(err.message || "Could not unlock that account.", "err");
    }
  }

  function removeUser(id) {
    var a = BIS.accounts.get(id);
    if (!a) return;
    if (!UI.confirm("Remove " + a.displayName + " (" + a.username + ")?\n\nThis deletes the account, its grades and its attendance records. It cannot be undone.")) return;
    try {
      BIS.accounts.remove(id, { who: admin.id });
      render();
      UI.toast("Account removed.", "ok");
    } catch (err) {
      UI.toast(err.message || "Could not remove that account.", "err");
    }
  }

  $("search").addEventListener("input", function () {
    searchTerm = this.value;
    render();
  });
  $("roleFilter").addEventListener("change", function () {
    roleFilter = this.value;
    render();
  });

  $("exportCsv").addEventListener("click", function () {
    try {
      var count = BIS.db.exportCredentials();
      UI.toast("Exported " + count + " account row(s) to CSV.", "ok");
    } catch (err) {
      UI.toast(err.message || "Could not export the account list.", "err");
    }
  });

  syncRoleFields();
  render();
})();
