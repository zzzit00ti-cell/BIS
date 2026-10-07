/* Login + first-run administrator setup. */
(function () {
  "use strict";

  var loginPanel = document.getElementById("loginPanel");
  var setupPanel = document.getElementById("setupPanel");
  var loginTitle = document.getElementById("authTitle");
  var loginSubtitle = document.getElementById("authSubtitle");
  var errorBox = document.getElementById("formError");
  var noticeBox = document.getElementById("formNotice");
  var demoBox = document.getElementById("demoBox");
  var demoList = document.getElementById("demoList");
  var usernameInput = document.getElementById("username");
  var passwordInput = document.getElementById("password");
  var loginBtn = document.getElementById("loginBtn");

  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
    noticeBox.classList.add("hidden");
  }

  function showNotice(message) {
    noticeBox.textContent = message;
    noticeBox.classList.remove("hidden");
    errorBox.classList.add("hidden");
  }

  function clearMessages() {
    errorBox.classList.add("hidden");
    noticeBox.classList.add("hidden");
  }

  function dashboardFor(role) {
    if (role === "admin") return "dashboard_admin.html";
    if (role === "teacher") return "dashboard_teacher.html";
    return "dashboard_student.html";
  }

  if (window.BIS.auth.getCurrentAccount()) {
    var current = BIS.auth.getCurrentAccount();
    window.location.replace(dashboardFor(current.role));
  }

  if (BIS.isFirstRun()) {
    loginPanel.classList.add("hidden");
    setupPanel.classList.remove("hidden");
    loginTitle.textContent = "Set up your school system";
    loginSubtitle.textContent = "One administrator account is created first. Everything else is added from the admin portal.";
    UI.passwordWidget(document.getElementById("setupPassword"), document.getElementById("setupPwFeedback"));
    document.getElementById("setupName").focus();
  }

  document.getElementById("togglePw").addEventListener("click", function () {
    var showing = passwordInput.type === "text";
    passwordInput.type = showing ? "password" : "text";
    this.textContent = showing ? "Show" : "Hide";
    this.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    passwordInput.focus();
  });

  Array.prototype.forEach.call(document.querySelectorAll("[data-generate]"), function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-generate"));
      input.value = BIS.accounts.randomPassword();
      input.dispatchEvent(new Event("input"));
      input.type = "text";
    });
  });

  var setupPassword = document.getElementById("setupPassword");
  var setupConfirm = document.getElementById("setupConfirm");
  var matchHint = document.getElementById("setupMatchHint");
  var usernameHint = document.getElementById("setupUsernameHint");
  var setupUsername = document.getElementById("setupUsername");

  [setupPassword, setupConfirm].forEach(function (input) {
    input.addEventListener("input", function () {
      if (!setupConfirm.value) {
        matchHint.textContent = "";
        return;
      }
      var same = setupConfirm.value === setupPassword.value;
      matchHint.textContent = same ? "Passwords match." : "Passwords do not match.";
      matchHint.style.color = same ? "var(--success)" : "var(--danger)";
    });
  });

  setupUsername.addEventListener("input", function () {
    var problems = BIS.accounts.usernameProblems(BIS.util.normalizeUsername(setupUsername.value));
    usernameHint.textContent = problems.length
      ? "Username " + problems.join(" ") + "."
      : "Looks good — this username is available to use.";
    usernameHint.style.color = problems.length ? "var(--danger)" : "var(--success)";
  });

  loginPanel.addEventListener("submit", async function (event) {
    event.preventDefault();
    clearMessages();
    var username = usernameInput.value.trim();
    var password = passwordInput.value;
    if (!username || !password) {
      showError("Enter both your username and password.");
      return;
    }
    loginBtn.disabled = true;
    loginBtn.textContent = "Signing in…";
    try {
      var result = await BIS.auth.verifyLogin(username, password);
      if (!result.ok) {
        showError(result.reason);
        passwordInput.value = "";
        passwordInput.focus();
        return;
      }
      BIS.auth.startSession(result.account);
      window.location.replace(
        result.mustChangePassword ? "change_password.html?required=1" : dashboardFor(result.account.role)
      );
    } catch (err) {
      showError(err.message || "Sign in failed. Please try again.");
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = "Sign in";
    }
  });

  setupPanel.addEventListener("submit", async function (event) {
    event.preventDefault();
    clearMessages();
    var setupBtn = document.getElementById("setupBtn");
    var form = {
      displayName: document.getElementById("setupName").value.trim(),
      username: setupUsername.value.trim(),
      email: document.getElementById("setupEmail").value.trim(),
      password: setupPassword.value
    };
    if (!form.displayName) return showError("Enter your full name.");
    if (form.password !== setupConfirm.value) return showError("The two passwords do not match.");
    var problems = BIS.accounts.passwordProblems(form.password);
    if (problems.length) return showError("Password needs " + problems.join(", ") + ".");

    setupBtn.disabled = true;
    setupBtn.textContent = "Creating…";
    try {
      var result = await BIS.bootstrapFirstAdmin(form, { withDemo: document.getElementById("setupDemo").checked });
      renderDemo(result);
      showNotice("Administrator created. You are now signed in.");
      setupPanel.classList.add("hidden");
      loginTitle.textContent = "Setup complete";
      loginSubtitle.textContent = "Your administrator account is ready. Sign in below to continue.";
      loginPanel.classList.remove("hidden");
      usernameInput.value = form.username;
      passwordInput.value = form.password;
      passwordInput.type = "text";
    } catch (err) {
      showError(err.message || "Could not create the administrator account.");
      setupBtn.disabled = false;
      setupBtn.textContent = "Create administrator";
    }
  });

  function renderDemo(result) {
    var rows = [{ name: "Administrator (you)", username: result.account.username, role: "admin" }];
    (result.demo || []).forEach(function (item) {
      var name = item.username;
      rows.push({ name: name, username: item.username, password: item.password, role: "user" });
    });
    if (!result.demo || !result.demo.length) {
      demoBox.classList.add("hidden");
      return;
    }
    demoList.innerHTML = "";
    var table = UI.el("table");
    rows.forEach(function (row) {
      table.appendChild(
        UI.el("tr", {}, [
          UI.el("td", { text: row.name }),
          UI.el("td", {}, [UI.el("code", { text: row.username })]),
          UI.el("td", {}, [UI.el("code", { text: row.password || "the password you just typed" })])
        ])
      );
    });
    demoList.appendChild(table);
    demoBox.classList.remove("hidden");
  }
})();
