/* Teacher attendance register. */
(function () {
  "use strict";

  var teacher = BIS.auth.requireAuth({ role: "teacher" });
  if (!teacher) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var STATUSES = [
    { key: "present", label: "Present" },
    { key: "absent", label: "Absent" },
    { key: "late", label: "Late" },
    { key: "excused", label: "Excused" }
  ];
  var records = {};

  function myGrades() {
    return teacher.profile.teachingGrades
      .split(",")
      .map(function (g) { return BIS.util.gradeKey(g); })
      .filter(Boolean);
  }

  function fillGrades() {
    var grades = myGrades();
    if (!grades.length) {
      $("gradeSelect").innerHTML = "";
      $("gradeSelect").append(UI.el("option", { value: "", text: "No grades assigned" }));
      $("gradeSelect").disabled = true;
      $("saveBtn").disabled = true;
      return;
    }
    $("gradeSelect").innerHTML = "";
    grades.forEach(function (grade) {
      $("gradeSelect").append(UI.el("option", { value: grade, text: "Grade " + grade }));
    });
  }

  function loadHistory() {
    var history = BIS.attendance.dates(14);
    var list = $("history");
    list.innerHTML = "";
    if (!history.length) {
      list.appendChild(UI.el("li", { text: "No attendance has been recorded yet." }));
      return;
    }
    history.forEach(function (date) {
      var rows = BIS.attendance.get(date);
      var present = rows.filter(function (r) { return r.status === "present"; }).length;
      var late = rows.filter(function (r) { return r.status === "late"; }).length;
      var absent = rows.filter(function (r) { return r.status === "absent" || r.status === "excused"; }).length;
      list.appendChild(
        UI.el("li", {}, [
          UI.el("button", {
            class: "btn btn-sm btn-ghost",
            style: "color:#0f172a",
            text: date,
            onclick: function () {
              $("dateInput").value = date;
              load();
            }
          }),
          UI.el("span", { class: "muted small", text: present + " present · " + late + " late · " + absent + " absent/excused" })
        ])
      );
    });
  }

  function summary() {
    var values = Object.keys(records).map(function (k) { return records[k]; });
    var counts = { present: 0, late: 0, absent: 0, excused: 0, blank: 0 };
    values.forEach(function (v) { counts[v || "blank"] += 1; });
    var tiles = [
      { value: values.length, label: "Students on register" },
      { value: counts.present, label: "Present" },
      { value: counts.late, label: "Late" },
      { value: counts.absent, label: "Absent" },
      { value: counts.excused, label: "Excused" },
      { value: counts.blank, label: "Not marked" }
    ];
    var host = $("summary");
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

  function statusPicker(studentId, current) {
    var wrap = UI.el("div", { class: "att-seg" });
    STATUSES.forEach(function (status) {
      wrap.appendChild(
        UI.el("button", {
          class: status.key,
          type: "button",
          text: status.label,
          "aria-pressed": current === status.key ? "true" : "false",
          onclick: function () {
            records[studentId] = records[studentId] === status.key ? "" : status.key;
            Array.prototype.forEach.call(wrap.querySelectorAll("button"), function (b) {
              b.setAttribute("aria-pressed", "false");
            });
            if (records[studentId]) {
              this.setAttribute("aria-pressed", "true");
            }
            summary();
          }
        })
      );
    });
    return wrap;
  }

  function load() {
    var grade = $("gradeSelect").value;
    var date = $("dateInput").value;
    records = {};
    var rows = $("rows");
    rows.innerHTML = "";
    $("rosterTitle").textContent = "Students · Grade " + (grade || "—") + " · " + (date || "—");

    if (!grade) {
      rows.appendChild(UI.el("tr", {}, [UI.el("td", { colspan: "4", class: "empty", text: "No grades are assigned to you yet. Ask an administrator to set your grades in user management." })]));
      summary();
      return;
    }

    var students = BIS.attendance.get(date, grade);
    if (!students.length) {
      rows.appendChild(UI.el("tr", {}, [UI.el("td", { colspan: "4", class: "empty", text: "No students in this grade yet." })]));
      summary();
      return;
    }

    students.forEach(function (entry) {
      records[entry.student.id] = entry.status;
      var rate = BIS.attendance.rateFor(entry.student.id);
      var row = UI.el("tr");
      row.appendChild(UI.el("td", {}, [UI.el("strong", { text: entry.student.displayName })]));
      row.appendChild(UI.el("td", { text: "Grade " + (BIS.util.gradeKeyFromProfile(entry.student.profile) || "—") }));
      row.appendChild(UI.el("td", { class: "small muted", text: rate.rate == null ? "—" : rate.present + "/" + rate.total + " (" + rate.rate + "%)" }));
      row.appendChild(UI.el("td", {}, [statusPicker(entry.student.id, entry.status)]));
      rows.appendChild(row);
    });
    summary();
  }

  $("saveBtn").addEventListener("click", function () {
    var grade = $("gradeSelect").value;
    var date = $("dateInput").value;
    if (!grade || !date) return UI.toast("Choose a grade and a date first.", "err");
    try {
      BIS.attendance.save(date, grade, records, { teacherId: teacher.id, who: teacher.id });
      UI.toast("Attendance saved for grade " + grade + " on " + date + ".", "ok");
      loadHistory();
      load();
    } catch (err) {
      UI.toast(err.message || "Could not save attendance.", "err");
    }
  });

  $("allPresent").addEventListener("click", function () {
    Object.keys(records).forEach(function (id) { records[id] = "present"; });
    load();
  });

  $("clearAll").addEventListener("click", function () {
    Object.keys(records).forEach(function (id) { delete records[id]; });
    load();
  });

  $("gradeSelect").addEventListener("change", load);
  $("dateInput").addEventListener("change", load);

  $("dateInput").value = UI.todayIso();
  fillGrades();
  load();
  loadHistory();
})();
