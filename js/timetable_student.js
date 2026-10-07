/* Student timetable: read-only weekly schedule for the student's grade. */
(function () {
  "use strict";

  var student = BIS.auth.requireAuth({ role: "student" });
  if (!student) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var grade = BIS.util.gradeKeyFromProfile(student.profile);
  var todayName = new Date().toLocaleDateString("en-GB", { weekday: "long" });

  $("gradeSelect").innerHTML = "";
  $("gradeSelect").append(
    UI.el("option", { value: grade, text: grade ? "Grade " + grade : "No grade set" })
  );
  $("gradeSelect").disabled = true;

  var grid = $("grid");
  grid.innerHTML = "";

  if (!grade) {
    grid.appendChild(
      UI.el("div", { class: "card" }, [
        UI.el("p", { class: "empty", text: "Your grade has not been set yet, so no timetable can be shown. Please ask the school office." })
      ])
    );
  } else {
    BIS.timetable.get(grade).forEach(function (day) {
      var card = UI.el("div", { class: "card" + (day.day === todayName ? " card-green" : "") }, [
        UI.el("h3", { text: day.day + (day.day === todayName ? " · today" : "") })
      ]);
      if (!day.periods.length) {
        card.appendChild(UI.el("p", { class: "empty", text: "No classes scheduled." }));
      } else {
        day.periods.forEach(function (period) {
          card.appendChild(
            UI.el("div", { class: "period-row" }, [
              UI.el("div", { class: "period-time", text: (period.start || "--:--") + "–" + (period.end || "--:--") }),
              UI.el("div", { class: "period-detail" }, [
                UI.el("b", { text: period.subject || "Period" }),
                UI.el("span", { class: "muted small", text: period.teacherName || "Teacher not set" })
              ]),
              UI.el("div", { class: "period-detail" }, [
                UI.el("b", { class: "small", text: period.room || "Room not set" })
              ])
            ])
          );
        });
      }
      grid.appendChild(card);
    });
  }

  $("printBtn").addEventListener("click", function () { window.print(); });
})();
