/* Student academic report card built from stored grades and attendance. */
(function () {
  "use strict";

  var student = BIS.auth.requireAuth({ role: "student" });
  if (!student) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var CONDUCT = [
    "Shows concern toward others",
    "Respects authority and rules",
    "Accepts correction in good spirit",
    "Listens attentively",
    "Follows instructions",
    "Completes work on time"
  ];

  function comment(mark) {
    if (mark == null) return "No mark recorded yet";
    if (mark >= 90) return "Excellent";
    if (mark >= 80) return "Very good";
    if (mark >= 70) return "Satisfactory";
    if (mark >= 60) return "Needs improvement";
    return "Requires support";
  }

  function gradeColour(mark) {
    if (mark == null) return "var(--muted)";
    if (mark >= 80) return "var(--success)";
    if (mark >= 60) return "var(--warning)";
    return "var(--danger)";
  }

  document.getElementById("studentName").textContent = student.displayName;
  document.getElementById("studentMeta").textContent =
    "ID " + student.id + " · Grade " + (BIS.util.gradeKeyFromProfile(student.profile) || "—") +
    (student.profile.teacherName ? " · Class teacher " + student.profile.teacherName : "");

  var grades = student.grades || {};
  var subjects = Object.keys(grades).sort();
  var average = BIS.grades.average(grades);
  var rate = BIS.attendance.rateFor(student.id);

  document.getElementById("bigAverage").textContent = average == null ? "—" : average;
  document.getElementById("bigAverage").style.color = gradeColour(average);
  document.getElementById("bigLetter").textContent = average == null ? "No marks yet" : "Letter grade " + BIS.grades.letter(average);

  var meta = document.getElementById("reportMeta");
  [
    { label: "Subjects graded", value: subjects.length },
    { label: "Highest mark", value: subjects.length ? Math.max.apply(null, subjects.map(function (s) { return grades[s]; })) : "—" },
    { label: "Attendance", value: rate.rate == null ? "—" : rate.rate + "%" },
    { label: "Days recorded", value: rate.total || "—" },
    { label: "Account status", value: student.status }
  ].forEach(function (item) {
    meta.appendChild(
      UI.el("div", { class: "meta-box" }, [
        UI.el("b", { text: item.label }),
        UI.el("span", { text: String(item.value) })
      ])
    );
  });

  var body = document.getElementById("grades");
  if (!subjects.length) {
    body.appendChild(UI.el("tr", {}, [UI.el("td", { colspan: "4", class: "empty", text: "No marks have been recorded yet. Your teachers will update this report." })]));
  } else {
    subjects.forEach(function (subject) {
      var mark = grades[subject];
      var letter = BIS.grades.letter(mark);
      var row = UI.el("tr");
      row.appendChild(UI.el("td", {}, [UI.el("strong", { text: subject })]));
      row.appendChild(UI.el("td", { class: "num", text: mark == null ? "—" : mark }));
      var gradeCell = UI.el("td", { class: "num", text: letter });
      gradeCell.style.color = gradeColour(mark);
      gradeCell.style.fontWeight = "800";
      row.appendChild(gradeCell);
      row.appendChild(UI.el("td", { class: "muted", text: comment(mark) }));
      body.appendChild(row);
    });
  }

  var conduct = document.getElementById("conduct");
  var stored = student.profile.conduct || {};
  CONDUCT.forEach(function (item, index) {
    var value = stored[item];
    conduct.appendChild(
      UI.el("li", {}, [
        UI.el("span", { text: item }),
        UI.el("span", { class: "badge " + (value ? "badge-green" : "badge-grey"), text: value || "Not rated" })
      ])
    );
  });

  var attendance = document.getElementById("attendance");
  var rows = BIS.attendance.forStudent(student.id, 10);
  if (!rows.length) {
    attendance.appendChild(UI.el("li", { text: "No attendance has been recorded yet." }));
  } else {
    rows.forEach(function (row) {
      var cls = row.status === "present" ? "badge-green" : row.status === "late" ? "badge-amber" : row.status === "absent" ? "badge-red" : "badge-grey";
      attendance.appendChild(
        UI.el("li", {}, [
          UI.el("span", { text: UI.formatDate(row.date) }),
          UI.el("span", { class: "badge " + cls, text: row.status })
        ])
      );
    });
  }

  document.getElementById("printBtn").addEventListener("click", function () {
    window.print();
  });
})();
