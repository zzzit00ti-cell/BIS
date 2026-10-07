/* Administrator timetable editor: per-grade, per-day period lists. */
(function () {
  "use strict";

  var admin = BIS.auth.requireAuth({ role: "admin" });
  if (!admin) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var grid = $("grid");
  var gradeInput = $("gradeSelect");
  var teacherSelect = $("teacherSelect");

  function currentGrade() {
    var value = gradeInput.value.trim().toUpperCase();
    return value || "10A";
  }

  function fillTeachers() {
    teacherSelect.innerHTML = "";
    teacherSelect.appendChild(UI.el("option", { value: "", text: "No teacher assigned" }));
    BIS.accounts.list({ role: "teacher" }).forEach(function (t) {
      teacherSelect.appendChild(UI.el("option", { value: t.id, text: t.displayName }));
    });
  }

  function periodNode(day, index, period) {
    var node = UI.el("div", { class: "period-row edit" });
    node.dataset.day = day;
    node.dataset.index = index;
    node.appendChild(UI.el("input", { type: "text", value: period.start || "", placeholder: "Start (e.g. 08:30)", maxlength: "10" }));
    node.appendChild(UI.el("input", { type: "text", value: period.end || "", placeholder: "End (e.g. 09:30)", maxlength: "10" }));
    var meta = UI.el("div", { class: "period-meta" }, [
      UI.el("input", { type: "text", value: period.subject || "", placeholder: "Subject", maxlength: "60" }),
      UI.el("input", { type: "text", value: period.room || "", placeholder: "Room", maxlength: "20" })
    ]);
    node.appendChild(meta);
    node.appendChild(
      UI.el("button", {
        class: "btn btn-sm btn-danger",
        type: "button",
        text: "Remove",
        onclick: function () {
          node.remove();
        }
      })
    );
    return node;
  }

  function render() {
    grid.innerHTML = "";
    var table = BIS.timetable.get(currentGrade());
    table.forEach(function (day) {
      var card = UI.el("div", { class: "card day-card card-accent" });
      card.appendChild(UI.el("h2", { text: day.day }));
      if (!day.periods.length) {
        card.appendChild(UI.el("p", { class: "muted small", text: "No periods yet." }));
      }
      day.periods.forEach(function (period, index) {
        card.appendChild(periodNode(day.day, index, period));
      });
      card.appendChild(
        UI.el("button", {
          class: "btn btn-sm btn-ghost",
          style: "color:#0f172a",
          text: "+ Add period",
          onclick: function () {
            card.insertBefore(periodNode(day.day, day.periods.length, {}), card.lastChild);
          }
        })
      );
      grid.appendChild(card);
    });
    $("status").innerHTML = "";
    $("status").append("Editing grade ");
    $("status").append(UI.el("strong", { text: currentGrade() }));
    $("status").append(". Teachers and students see the timetable for their own grade.");
  }

  function collect() {
    var out = {};
    BIS.WEEKDAYS.forEach(function (day) {
      out[day] = [];
    });
    Array.prototype.forEach.call(grid.querySelectorAll(".period-row"), function (node) {
      var inputs = node.querySelectorAll("input");
      var teacher = teacherSelect.selectedOptions[0];
      var teacherId = teacherSelect.value;
      var teacherName = "";
      BIS.accounts.list({ role: "teacher" }).forEach(function (t) {
        if (t.id === teacherId) teacherName = t.displayName;
      });
      out[node.dataset.day].push({
        start: inputs[0].value.trim(),
        end: inputs[1].value.trim(),
        subject: inputs[2].value.trim(),
        room: inputs[3].value.trim(),
        teacherId: teacherId,
        teacherName: teacherName
      });
    });
    return out;
  }

  $("saveAll").addEventListener("click", function () {
    var data = collect();
    try {
      BIS.WEEKDAYS.forEach(function (day) {
        BIS.timetable.setDay(currentGrade(), day, data[day], { who: admin.id });
      });
      UI.toast("Timetable saved for grade " + currentGrade() + ".", "ok");
    } catch (err) {
      UI.toast(err.message || "Could not save the timetable.", "err");
    }
  });

  $("addPeriod").addEventListener("click", function () {
    var firstCard = grid.querySelector(".day-card");
    if (firstCard) firstCard.querySelector(".btn-sm").click();
  });

  gradeInput.addEventListener("change", render);
  gradeInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      render();
    }
  });

  fillTeachers();
  render();
})();
