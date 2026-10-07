/* Teacher gradebook: one editable column per subject, per student. */
(function () {
  "use strict";

  var teacher = BIS.auth.requireAuth({ role: "teacher" });
  if (!teacher) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var subjects = [];
  var students = [];
  var draft = {};

  function myGrades() {
    return teacher.profile.teachingGrades
      .split(",")
      .map(function (g) { return BIS.util.gradeKey(g); })
      .filter(Boolean);
  }

  function knownSubjects() {
    var set = {};
    if (teacher.profile.subject) set[teacher.profile.subject] = true;
    BIS.accounts.list({ role: "student" }).forEach(function (s) {
      Object.keys(s.grades || {}).forEach(function (subject) { set[subject] = true; });
    });
    return Object.keys(set).sort();
  }

  function fillGradeSelect() {
    var grades = myGrades();
    $("gradeSelect").innerHTML = "";
    if (!grades.length) {
      $("gradeSelect").append(UI.el("option", { value: "", text: "No grades assigned" }));
      $("saveBtn").disabled = true;
      return false;
    }
    grades.forEach(function (grade) { $("gradeSelect").append(UI.el("option", { value: grade, text: "Grade " + grade })); });
    return true;
  }

  function renderSubjects() {
    var bar = $("subjects");
    bar.innerHTML = "";
    if (!subjects.length) {
      bar.append(UI.el("span", { class: "muted small", text: "No subjects yet — add one to start recording marks." }));
      return;
    }
    subjects.forEach(function (subject) {
      bar.appendChild(
        UI.el("button", {
          class: "chip",
          type: "button",
          title: "Remove " + subject,
          text: subject + " ✕",
          onclick: function () {
            subjects = subjects.filter(function (s) { return s !== subject; });
            renderSubjects();
            load();
          }
        })
      );
    });
  }

  function renderSummary() {
    var averages = students.map(function (s) { return BIS.grades.average(draft[s.id] || {}); }).filter(function (v) { return v != null; });
    var classAvg = averages.length
      ? Math.round((averages.reduce(function (a, b) { return a + b; }, 0) / averages.length) * 10) / 10
      : null;
    var tiles = [
      { value: students.length, label: "Students" },
      { value: subjects.length, label: "Subjects" },
      { value: averages.length, label: "With marks" },
      { value: classAvg == null ? "—" : classAvg, label: "Class average" },
      { value: classAvg == null ? "—" : BIS.grades.letter(classAvg), label: "Class grade" }
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

  function renderHead() {
    var head = $("head");
    head.innerHTML = "";
    var row = UI.el("tr", {}, [
      UI.el("th", { text: "Student" }),
      UI.el("th", { class: "num", text: "Average" }),
      UI.el("th", { class: "num", text: "Grade" }),
      UI.el("th", { text: "Attendance" })
    ]);
    subjects.forEach(function (subject) {
      row.appendChild(UI.el("th", { class: "num subject-head", text: subject }));
    });
    head.appendChild(row);
  }

  function load() {
    var grade = $("gradeSelect").value;
    students = [];
    draft = {};
    var rows = $("rows");
    rows.innerHTML = "";
    renderHead();
    $("rosterTitle").textContent = "Students · Grade " + (grade || "—");

    if (!grade) {
      rows.appendChild(UI.el("tr", {}, [UI.el("td", { colspan: "4", class: "empty", text: "No grades are assigned to you yet. Ask an administrator to set them in user management." })]));
      renderSummary();
      return;
    }

    subjects = knownSubjects();
    renderSubjects();

    students = BIS.accounts.list({ role: "student" }).filter(function (s) {
      return BIS.util.gradeKeyFromProfile(s.profile) === grade;
    });

    if (!students.length) {
      rows.appendChild(UI.el("tr", {}, [UI.el("td", { colspan: "4", class: "empty", text: "No students in this grade yet." })]));
      renderSummary();
      return;
    }

    students.forEach(function (s) {
      draft[s.id] = Object.assign({}, s.grades || {});
      var row = UI.el("tr");
      row.dataset.studentId = s.id;
      row.appendChild(UI.el("td", {}, [
        UI.el("strong", { text: s.displayName }),
        UI.el("div", { class: "muted small", text: s.id + (s.profile.section ? " · Section " + s.profile.section : "") })
      ]));
      subjects.forEach(function (subject) {
        var input = UI.el("input", {
          type: "number",
          min: "0",
          max: "100",
          step: "0.5",
          value: draft[s.id][subject] != null ? draft[s.id][subject] : "",
          placeholder: "0–100",
          dataset: { subject: subject }
        });
        row.appendChild(UI.el("td", { class: "num" }, [input]));
      });
      row.appendChild(UI.el("td", { class: "num letter", text: "—" }));
      var rate = BIS.attendance.rateFor(s.id);
      row.appendChild(UI.el("td", { class: "small muted", text: rate.rate == null ? "No data" : rate.rate + "%" }));
      rows.appendChild(row);
    });

    updateDerived();
    renderSummary();
  }

  function updateDerived() {
    Array.prototype.forEach.call($("rows").querySelectorAll("tr[data-student-id]"), function (row) {
      var id = row.dataset.studentId;
      Array.prototype.forEach.call(row.querySelectorAll("input[data-subject]"), function (input) {
        var raw = input.value.trim();
        if (raw === "") delete draft[id][input.dataset.subject];
        else draft[id][input.dataset.subject] = Math.max(0, Math.min(100, Number(raw)));
      });
      var avg = BIS.grades.average(draft[id]);
      var avgCell = row.querySelector("td.letter");
      avgCell.textContent = avg == null ? "—" : avg;
      avgCell.style.color = avg == null ? "var(--muted)" : avg >= 80 ? "var(--success)" : avg >= 60 ? "var(--warning)" : "var(--danger)";
    });
  }

  $("addSubject").addEventListener("click", function () {
    var name = window.prompt("Subject name:");
    name = (name || "").trim();
    if (!name) return;
    if (subjects.indexOf(name) < 0) subjects.push(name);
    renderSubjects();
    load();
  });

  $("saveBtn").addEventListener("click", function () {
    if (!students.length) return UI.toast("No students to save.", "err");
    var saved = 0;
    var errors = [];
    students.forEach(function (s) {
      try {
        BIS.accounts.update(s.id, { grades: draft[s.id] }, { who: teacher.id, teacherId: teacher.id });
        saved += 1;
      } catch (err) {
        errors.push(s.displayName + ": " + err.message);
      }
    });
    if (errors.length) UI.toast(errors.join(" · "), "err");
    else UI.toast("Saved marks for " + saved + " student(s).", "ok");
  });

  $("gradeSelect").addEventListener("change", load);
  $("rows").addEventListener("input", function (e) {
    if (e.target.tagName === "INPUT") {
      updateDerived();
      renderSummary();
    }
  });

  if (fillGradeSelect()) load();
})();
