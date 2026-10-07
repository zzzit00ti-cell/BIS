/* Teacher dashboard: real counts from stored data. */
(function () {
  "use strict";

  var teacher = BIS.auth.requireAuth({ role: "teacher" });
  if (!teacher) return;
  if (!BIS.auth.requirePasswordChange()) return;

  function myGrades() {
    return teacher.profile.teachingGrades
      .split(",")
      .map(function (g) { return BIS.util.gradeKey(g); })
      .filter(Boolean);
  }

  function myStudents() {
    var grades = myGrades();
    return BIS.accounts.list({ role: "student" }).filter(function (s) {
      return s.status === "Active" && grades.indexOf(BIS.util.gradeKeyFromProfile(s.profile)) >= 0;
    });
  }

  function renderProfile() {
    var card = document.getElementById("profileCard");
    card.innerHTML = "";
    card.appendChild(UI.avatar(teacher.displayName, teacher.photoDataUrl));
    card.appendChild(UI.el("h3", { text: teacher.displayName }));
    card.appendChild(UI.el("p", { class: "muted", text: teacher.profile.subject ? teacher.profile.subject + " teacher" : "Teacher" }));
    card.appendChild(UI.el("p", { class: "small muted", text: "ID: " + teacher.id }));
    if (myGrades().length) {
      card.appendChild(UI.el("p", { class: "small", text: "Grades: " + myGrades().join(", ") }));
    }
    card.appendChild(UI.el("a", { class: "btn btn-sm", href: "profile.html", text: "My profile" }));
  }

  function renderStats() {
    var students = myStudents();
    var withGrades = students.filter(function (s) { return Object.keys(s.grades || {}).length > 0; });
    var avg = withGrades.length
      ? Math.round(
          (withGrades.reduce(function (sum, s) { return sum + BIS.grades.average(s.grades); }, 0) / withGrades.length) * 10
        ) / 10
      : null;
    var gradedToday = BIS.accounts.list({ role: "teacher" }).filter(function (t) {
      return t.security.lastLoginAt && t.security.lastLoginAt.slice(0, 10) === UI.todayIso();
    }).length;
    var attendanceDates = BIS.attendance.dates(60).length;

    var tiles = [
      { value: myGrades().length || "—", label: "Grades assigned" },
      { value: students.length, label: "My students" },
      { value: withGrades.length, label: "With grades recorded" },
      { value: avg == null ? "—" : avg, label: "Average mark" },
      { value: attendanceDates, label: "Attendance days logged" },
      { value: gradedToday, label: "Staff active today" }
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

  function renderToday() {
    var list = document.getElementById("todayList");
    list.innerHTML = "";
    var dayName = new Date().toLocaleDateString("en-GB", { weekday: "long" });
    var periods = [];
    myGrades().forEach(function (grade) {
      BIS.timetable.get(grade).forEach(function (entry) {
        entry.periods.forEach(function (period) {
          if (entry.day === dayName) periods.push({ grade: grade, period: period });
        });
      });
    });
    document.getElementById("timetableHint").textContent = periods.length
      ? periods.length + " period(s) scheduled for you on " + dayName + "."
      : "Your schedule for " + dayName + " has not been published yet.";

    if (!periods.length) {
      list.appendChild(UI.el("li", { text: "No periods scheduled for " + dayName + "." }));
      return;
    }
    periods.forEach(function (item) {
      list.appendChild(
        UI.el("li", {}, [
          UI.el("span", {}, [
            UI.el("strong", { text: item.period.subject || "Period" }),
            UI.el("span", { class: "muted small", text: " · Grade " + item.grade + (item.period.room ? " · " + item.period.room : "") })
          ]),
          UI.el("span", { class: "muted small", text: (item.period.start || "") + "–" + (item.period.end || "") })
        ])
      );
    });
  }

  function renderStudents() {
    var list = document.getElementById("studentList");
    list.innerHTML = "";
    var students = myStudents().slice(0, 8);
    if (!students.length) {
      list.appendChild(UI.el("li", { text: "No students are assigned to your grades yet. Ask an administrator." }));
      return;
    }
    students.forEach(function (s) {
      var rate = BIS.attendance.rateFor(s.id);
      list.appendChild(
        UI.el("li", {}, [
          UI.el("span", {}, [
            UI.el("strong", { text: s.displayName }),
            UI.el("span", { class: "muted small", text: " · Grade " + (s.profile.grade || "—") + (s.profile.section ? s.profile.section : "") })
          ]),
          UI.el("span", { class: "muted small", text: rate.rate == null ? "No attendance yet" : rate.rate + "% attendance" })
        ])
      );
    });
    if (myStudents().length > 8) {
      list.appendChild(UI.el("li", { class: "muted small", text: "and " + (myStudents().length - 8) + " more…" }));
    }
  }

  renderProfile();
  renderStats();
  renderToday();
  renderStudents();
})();
