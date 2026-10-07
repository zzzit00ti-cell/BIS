/* Shared read-only announcement browser for teachers and students. */
(function () {
  "use strict";

  var account = BIS.auth.requireAuth({ role: ["teacher", "student"] });
  if (!account) return;
  if (!BIS.auth.requirePasswordChange()) return;

  var $ = function (id) { return document.getElementById(id); };
  var selectedId = 0;

  function visible() {
    var term = $("searchInput").value.trim().toLowerCase();
    return BIS.announcements.list(account.role).filter(function (item) {
      if ($("pinnedOnly").checked && !item.pinned) return false;
      if (!term) return true;
      return (item.title + " " + item.body).toLowerCase().indexOf(term) >= 0;
    });
  }

  function renderDetail(item) {
    var host = $("detail");
    host.innerHTML = "";
    if (!item) {
      host.appendChild(UI.el("h2", { text: "Select an announcement" }));
      host.appendChild(UI.el("p", { class: "muted", text: "Choose an item from the list to read the full text." }));
      return;
    }
    host.appendChild(UI.el("h2", { text: (item.pinned ? "📌 " : "") + item.title }));
    host.appendChild(
      UI.el("p", { class: "muted small", text: item.date + " · by " + (item.author || "Administration") })
    );
    host.appendChild(UI.el("div", { class: "announce-body", text: item.body }));
  }

  function render() {
    var items = visible();
    var list = $("list");
    list.innerHTML = "";
    $("count").textContent = items.length + " announcement(s)";

    if (!items.length) {
      list.appendChild(UI.el("li", { class: "empty", text: "No announcements to show." }));
      renderDetail(null);
      return;
    }

    if (!items.some(function (i) { return i.id === selectedId; })) selectedId = items[0].id;
    var current = null;

    items.forEach(function (item) {
      if (item.id === selectedId) current = item;
      list.appendChild(
        UI.el("li", { class: item.id === selectedId ? "active" : "" }, [
          UI.el("button", {
            class: "linkish",
            type: "button",
            text: (item.pinned ? "📌 " : "") + item.title,
            onclick: function () {
              selectedId = item.id;
              render();
            }
          }),
          UI.el("span", { class: "muted small", text: item.date })
        ])
      );
    });

    renderDetail(current);
  }

  $("searchInput").addEventListener("input", render);
  $("pinnedOnly").addEventListener("change", render);

  render();
})();
