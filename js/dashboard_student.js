/* Student dashboard: real averages, attendance and announcements. */
(function () {
  "use strict";

  var student = BIS.auth.requireAuth({ role: "student" });
  if (!student) return;
  if (!BIS.auth.requirePasswordChange()) return;

  function renderProfile() {
    var card = document.getElementById("profileCard");
    card.innerHTML = "";
    card.appendChild(UI.avatar(student.displayName, student.photoDataUrl));
    card.appendChild(UI.el("h3", { text: student.displayName }));
    card.appendChild(UI.el("p", { class: "muted", text: "Grade " + (student.profile.grade || "—") + (student.profile.section ? " · Section " + student.profile.section : "") }));
    card.appendChild(UI.el("p", { class: "small muted", text: "ID: " + student.id }));
    if (student.profile.teacherName) {
      card.appendChild(UI.el("p", { class: "small", text: "Class teacher: " + student.profile.teacherName }));
    }
    card.appendChild(UI.el("a", { class: "btn btn-sm", href: "profile.html", text: "My profile" }));
  }

  function renderStats() {
    var avg = BIS.grades.average(student.grades);
    var rate = BIS.attendance.rateFor(student.id);
    var subjectCount = Object.keys(student.grades || {}).length;
    var dayName = new Date().toLocaleDateString("en-GB", { weekday: "long" });
    var todayPeriods = 0;
    if (student.profile.grade) {
      todayPeriods = BIS.timetable.get(BIS.util.gradeKeyFromProfile(student.profile))
        .filter(function (d) { return d.day === dayName; })
        .reduce(function (sum, d) { return sum + d.periods.length; }, 0);
    }
    var announcements = BIS.announcements.list("student");

    var tiles = [
      { value: avg == null ? "—" : avg, label: "My average mark" },
      { value: avg == null ? "—" : BIS.grades.letter(avg), label: "Letter grade" },
      { value: subjectCount, label: "Subjects graded" },
      { value: rate.rate == null ? "—" : rate.rate + "%", label: "Attendance rate" },
      { value: todayPeriods, label: "Periods today" },
      { value: announcements.length, label: "Announcements" }
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

    document.getElementById("timetableHint").textContent = student.profile.grade
      ? "Your weekly schedule for grade " + BIS.util.gradeKeyFromProfile(student.profile) + "."
      : "Your grade has not been set yet, so no timetable can be shown. Ask your class teacher.";
  }

  function renderNews() {
    var list = document.getElementById("newsList");
    list.innerHTML = "";
    var items = BIS.announcements.list("student").slice(0, 6);
    if (!items.length) {
      list.appendChild(UI.el("li", { text: "No announcements yet." }));
      return;
    }
    items.forEach(function (item) {
      list.appendChild(
        UI.el("li", {}, [
          UI.el("span", {}, [
            UI.el("strong", { text: (item.pinned ? "📌 " : "") + item.title }),
            UI.el("div", { class: "muted small", text: (item.body || "").slice(0, 90) })
          ]),
          UI.el("span", { class: "muted small", text: UI.formatDate(item.createdAt) })
        ])
      );
    });
  }

  function renderAttendance() {
    var list = document.getElementById("attendanceList");
    list.innerHTML = "";
    var rows = BIS.attendance.forStudent(student.id, 8);
    if (!rows.length) {
      list.appendChild(UI.el("li", { text: "No attendance recorded yet." }));
      return;
    }
    rows.forEach(function (row) {
      list.appendChild(
        UI.el("li", {}, [
          UI.el("span", { text: UI.formatDate(row.date) }),
          UI.el("span", { class: "badge " + badgeFor(row.status), text: row.status })
        ])
      );
    });
  }

  function badgeFor(status) {
    if (status === "present") return "badge-green";
    if (status === "late") return "badge-amber";
    if (status === "absent") return "badge-red";
    return "badge-grey";
  }

  renderProfile();
  renderStats();
  renderNews();
  renderAttendance();
})();
