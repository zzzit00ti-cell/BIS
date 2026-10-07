/* Password change, including the forced change after an administrator sets one. */
(function () {
  "use strict";

  var acct = BIS.auth.requireAuth({});
  if (!acct) return;

  var required = new URLSearchParams(window.location.search).get("required") === "1" || acct.security.mustChangePassword;
  if (required) document.getElementById("requiredNotice").classList.remove("hidden");

  var currentInput = document.getElementById("current");
  var nextInput = document.getElementById("next");
  var confirmInput = document.getElementById("confirm");
  var matchHint = document.getElementById("matchHint");
  var errorBox = document.getElementById("formError");
  var okBox = document.getElementById("formOk");
  var submitBtn = document.getElementById("submitBtn");

  UI.passwordWidget(nextInput, document.getElementById("pwFeedback"));

  Array.prototype.forEach.call(document.querySelectorAll("[data-generate]"), function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-generate"));
      input.value = BIS.accounts.randomPassword();
      input.dispatchEvent(new Event("input"));
    });
  });

  [nextInput, confirmInput].forEach(function (input) {
    input.addEventListener("input", function () {
      if (!confirmInput.value) {
        matchHint.textContent = "";
        return;
      }
      var same = confirmInput.value === nextInput.value;
      matchHint.textContent = same ? "Passwords match." : "Passwords do not match.";
      matchHint.style.color = same ? "var(--success)" : "var(--danger)";
    });
  });

  document.getElementById("pwForm").addEventListener("submit", async function (event) {
    event.preventDefault();
    errorBox.classList.add("hidden");
    okBox.classList.add("hidden");

    var current = currentInput.value;
    var next = nextInput.value;
    var confirm = confirmInput.value;

    if (!current || !next) return fail("Fill in every field.");
    if (next !== confirm) return fail("The two new passwords do not match.");
    var problems = BIS.accounts.passwordProblems(next);
    if (problems.length) return fail("Password needs " + problems.join(", ") + ".");
    if (next === current) return fail("The new password must be different from the current one.");

    submitBtn.disabled = true;
    submitBtn.textContent = "Updating…";
    try {
      var check = await BIS.auth.verifyLogin(acct.username, current);
      if (!check.ok) return fail("Your current password is not correct.");
      await BIS.accounts.setPassword(acct.id, next, {
        who: acct.id,
        currentPassword: current,
        mustChangePassword: false
      });
      okBox.textContent = "Password updated. Returning to your dashboard…";
      okBox.classList.remove("hidden");
      currentInput.value = nextInput.value = confirmInput.value = "";
      setTimeout(function () {
        window.location.href =
          acct.role === "admin"
            ? "dashboard_admin.html"
            : acct.role === "teacher"
            ? "dashboard_teacher.html"
            : "dashboard_student.html";
      }, 1200);
    } catch (err) {
      fail(err.message || "Could not update the password.");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Update password";
    }
  });

  function fail(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
  }
})();
