/* Admin announcement composer. */
(function () {
  "use strict";

  var admin = BIS.auth.requireAuth({ role: "admin" });
  if (!admin) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var editingId = 0;

  function resetForm() {
    editingId = 0;
    $("form").reset();
    $("formTitle").textContent = "Publish an announcement";
    $("submitBtn").textContent = "Publish";
    $("formHint").textContent = "";
  }

  function startEdit(item) {
    editingId = item.id;
    $("titleInput").value = item.title;
    $("bodyInput").value = item.body;
    $("audienceSelect").value = item.audience;
    $("pinnedInput").checked = Boolean(item.pinned);
    $("formTitle").textContent = "Edit announcement";
    $("submitBtn").textContent = "Save changes";
    $("formHint").textContent = "Editing announcement #" + item.id;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function render() {
    var filter = $("filterSelect").value;
    var items = BIS.announcements.list(filter === "all" ? null : filter);
    var list = $("list");
    list.innerHTML = "";
    if (!items.length) {
      list.appendChild(UI.el("li", { class: "empty", text: "No announcements published yet." }));
      return;
    }
    items.forEach(function (item) {
      var actions = UI.el("span", {}, [
        UI.el("button", { class: "btn btn-sm", type: "button", text: "Edit", onclick: function () { startEdit(item); } }),
        UI.el("button", {
          class: "btn btn-sm btn-danger",
          type: "button",
          text: "Delete",
          onclick: function () {
            if (!UI.confirm("Delete \"" + item.title + "\"? This cannot be undone.")) return;
            try {
              BIS.announcements.delete(item.id, { who: admin.id });
              if (editingId === item.id) resetForm();
              render();
              UI.toast("Announcement deleted.", "ok");
            } catch (err) {
              UI.toast(err.message, "err");
            }
          }
        })
      ]);
      list.appendChild(
        UI.el("li", {}, [
          UI.el("span", {}, [
            UI.el("strong", { text: (item.pinned ? "📌 " : "") + item.title }),
            UI.el("div", { class: "muted small", text: item.date + " · audience: " + item.audience + " · by " + (item.author || "Administration") })
          ]),
          actions
        ])
      );
    });
  }

  $("form").addEventListener("submit", function (e) {
    e.preventDefault();
    try {
      BIS.announcements.save(
        {
          id: editingId,
          title: $("titleInput").value,
          body: $("bodyInput").value,
          audience: $("audienceSelect").value,
          pinned: $("pinnedInput").checked
        },
        { who: admin.id, authorName: admin.displayName }
      );
      UI.toast(editingId ? "Announcement updated." : "Announcement published.", "ok");
      resetForm();
      render();
    } catch (err) {
      UI.toast(err.message || "Could not save the announcement.", "err");
    }
  });

  $("resetBtn").addEventListener("click", resetForm);
  $("filterSelect").addEventListener("change", render);

  render();
})();
