/* Teacher timetable: only the periods assigned to the signed-in teacher. */
(function () {
  "use strict";

  var teacher = BIS.auth.requireAuth({ role: "teacher" });
  if (!teacher) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };

  function myGrades() {
    return teacher.profile.teachingGrades
      .split(",")
      .map(function (g) { return BIS.util.gradeKey(g); })
      .filter(Boolean);
  }

  function load() {
    var grade = $("gradeSelect").value;
    var grid = $("grid");
    grid.innerHTML = "";
    var total = 0;
    var days = BIS.timetable.get(grade);

    if (!grade) {
      grid.appendChild(UI.el("div", { class: "card" }, [
        UI.el("p", { class: "empty", text: "No grades are assigned to you yet. Ask an administrator to set them in user management." })
      ]));
      renderSummary(0, 0);
      return;
    }

    days.forEach(function (day) {
      var mine = day.periods.filter(function (p) {
        return !p.teacherId || p.teacherId === teacher.id || p.teacherName === teacher.displayName;
      });
      total += mine.length;
      var card = UI.el("div", { class: "card" }, [
        UI.el("h3", { text: day.day }),
        UI.el("p", { class: "muted small", text: mine.length + " of " + day.periods.length + " period(s) — Grade " + grade })
      ]);
      if (!mine.length) {
        card.appendChild(UI.el("p", { class: "empty", text: "No periods assigned to you." }));
      } else {
        mine.forEach(function (period) {
          card.appendChild(
            UI.el("div", { class: "period-row" }, [
              UI.el("div", { class: "period-time", text: (period.start || "--:--") + "–" + (period.end || "--:--") }),
              UI.el("div", { class: "period-detail" }, [
                UI.el("b", { text: period.subject || "Period" }),
                UI.el("span", { class: "muted small", text: "Grade " + grade })
              ]),
              UI.el("div", { class: "period-detail" }, [
                UI.el("b", { class: "small", text: period.room || "Room not set" }),
                UI.el("span", { class: "muted small", text: period.teacherName || teacher.displayName })
              ])
            ])
          );
        });
      }
      grid.appendChild(card);
    });

    renderSummary(total, days.reduce(function (n, d) { return n + d.periods.length; }, 0));
  }

  function renderSummary(mine, total) {
    var host = $("summary");
    host.innerHTML = "";
    [
      { value: BIS.WEEKDAYS.length, label: "School days" },
      { value: mine, label: "My periods per week" },
      { value: total, label: "All periods in grade" },
      { value: total ? Math.round((mine / total) * 100) + "%" : "—", label: "My teaching load" }
    ].forEach(function (tile) {
      host.appendChild(
        UI.el("div", { class: "stat-card" }, [
          UI.el("div", { class: "stat-value", text: String(tile.value) }),
          UI.el("div", { class: "stat-label", text: tile.label })
        ])
      );
    });
  }

  var grades = myGrades();
  $("gradeSelect").innerHTML = "";
  if (grades.length) {
    grades.forEach(function (g) { $("gradeSelect").append(UI.el("option", { value: g, text: "Grade " + g })); });
  } else {
    $("gradeSelect").append(UI.el("option", { value: "", text: "No grades assigned" }));
  }

  $("gradeSelect").addEventListener("change", load);
  $("printBtn").addEventListener("click", function () { window.print(); });

  load();
})();
