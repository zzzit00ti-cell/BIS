/* Shared page shell: header, navigation, footer with social links, auth guards, UI helpers. */
(function () {
  "use strict";

  var LOGO = "photo_5985567029475788521_y.jpg";

  var PUBLIC_NAV = [
    { href: "index.html", label: "Home" },
    { href: "about.html", label: "About" },
    { href: "gallary.html", label: "Gallery" },
    { href: "contact-us.html", label: "Contact" }
  ];

  var ROLE_NAV = {
    admin: [
      { href: "dashboard_admin.html", label: "Dashboard" },
      { href: "user_management_admin.html", label: "Users" },
      { href: "announcement_admin.html", label: "Announcements" },
      { href: "timetable_admin.html", label: "Timetables" },
      { href: "settings_admin.html", label: "Settings" }
    ],
    teacher: [
      { href: "dashboard_teacher.html", label: "Dashboard" },
      { href: "attendance_teacher.html", label: "Attendance" },
      { href: "timetable_teacher.html", label: "My Timetable" },
      { href: "reports_student_teacher_view.html", label: "Grades" },
      { href: "announcements_teacher.html", label: "Announcements" }
    ],
    student: [
      { href: "dashboard_student.html", label: "Dashboard" },
      { href: "timetable_student.html", label: "My Timetable" },
      { href: "reports_academic.html", label: "My Grades" },
      { href: "announcements_student.html", label: "Announcements" }
    ]
  };

  var SOCIAL_ICONS = {
    facebook:
      '<path fill="currentColor" d="M9.1 15.6v-6.4H7.2V6.6h1.9V5.1c0-1.9 1.1-3 3.1-3 .9 0 1.6.1 1.8.1v2.1h-1.2c-1 0-1.2.5-1.2 1.2v1.1h2.3l-.3 2.6h-2v6.4H9.1z"/>',
    telegram:
      '<path fill="currentColor" d="M9.8 15.1c-3.4 1.5-5.2-.8-5.2-.8s-1.1-1.2.2-1.4c1-.1 1.8-.4 1.8-.4s.4.2 2.4 1c.1 0 .1 0 .2 0-1.3-1.9-1-2.5-1-2.5s-.1-.1 0-.2c.1-.2.2-.1.2-.1 1.1.7 1.6 1.4 1.6 1.4s.8-1.3 2.3-1.9c.1 0 .1 0 .2 0 1.1.4 1.4 1.3 1.4 1.3s.7.9 2.1.3c.4-.2.4-.5.2-.7-.5-1.1-1.2-1.9-1.2-1.9s1.2 0 2 .8c.5.5.7 1.2.5 2-.6 2.2-3 3.2-3 3.2z"/>',
    youtube:
      '<path fill="currentColor" d="M13.5 5.3c-.2-.7-.8-1.2-1.5-1.4C10.7 3.7 7.6 3.7 7.6 3.7s-3.1 0-4.4.2c-.7.2-1.3.7-1.5 1.4-.2 1.3-.2 2.7-.2 2.7s0 1.4.2 2.7c.2.7.8 1.2 1.5 1.4 1.3.2 4.4.2 4.4.2s3.1 0 4.4-.2c.7-.2 1.3-.7 1.5-1.4.2-1.3.2-2.7.2-2.7s0-1.4-.2-2.7zM6.2 9.8V6.2l2.5 1.8-2.5 1.8z"/>',
    tiktok:
      '<path fill="currentColor" d="M11.4 3h-1.8v8.1a1.9 1.9 0 1 1-1.9-1.9c.2 0 .4 0 .5.1V7.4a3.7 3.7 0 1 0 3.2 3.7V6.3c.7.5 1.6.9 2.6 1v-1.9c-1.4 0-2.6-1.1-2.6-2.4V3z"/>'
  };

  function settings() {
    try {
      return window.BIS ? window.BIS.settings.get() : null;
    } catch (e) {
      return null;
    }
  }

  function activeHref() {
    var file = window.location.pathname.split("/").pop() || "index.html";
    return decodeURIComponent(file);
  }

  function navFor(acct) {
    if (!acct) return PUBLIC_NAV;
    return (ROLE_NAV[acct.role] || []).slice();
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === "class") node.className = attrs[key];
      else if (key === "text") node.textContent = attrs[key];
      else if (key === "html") node.innerHTML = attrs[key];
      else if (key === "dataset") Object.keys(attrs.dataset).forEach(function (d) { node.dataset[d] = attrs.dataset[d]; });
      else if (key.slice(0, 2) === "on") node.addEventListener(key.slice(2), attrs[key]);
      else if (attrs[key] != null) node.setAttribute(key, attrs[key]);
    });
    (children || []).forEach(function (child) {
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function renderHeader(acct) {
    var host = document.getElementById("site-header");
    if (!host) return;
    var s = settings() || {};
    var name = s.schoolName || "Bonafide International School";
    var tagline = s.tagline || "Center of Quality Education";
    var current = activeHref();
    var links = navFor(acct);
    if (acct) links.push({ href: "profile.html", label: "Profile" });

    var nav = el("nav", { class: "site-nav", id: "site-nav", "aria-label": "Main" });
    links.forEach(function (item) {
      var attrs = { href: item.href, text: item.label };
      if (item.href === current) attrs["aria-current"] = "page";
      nav.appendChild(el("a", attrs));
    });
    if (acct) {
      nav.appendChild(
        el("a", {
          href: "#",
          text: "Log out",
          onclick: function (e) {
            e.preventDefault();
            window.BIS.auth.endSession();
            window.location.href = "login.html";
          }
        })
      );
    } else {
      nav.appendChild(el("a", { href: "login.html", text: "Log in" }));
    }

    var toggle = el("button", {
      class: "nav-toggle",
      type: "button",
      "aria-label": "Menu",
      "aria-expanded": "false",
      text: "☰",
      onclick: function () {
        var open = nav.classList.toggle("open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      }
    });

    host.className = "site-header";
    host.innerHTML = "";
    host.appendChild(
      el("div", { class: "bar" }, [
        el("div", { class: "brand" }, [
          el("div", { class: "logo" }, [el("img", { src: LOGO, alt: name + " logo" })]),
          el("div", {}, [
            el("div", { class: "school-name", text: name }),
            el("div", { class: "school-tagline" }, [
              document.createTextNode(tagline + " · "),
              el("a", { href: "contact-us.html", text: "Contact" })
            ])
          ])
        ]),
        toggle,
        nav
      ])
    );
  }

  function socialLinks(s) {
    var social = (s && s.social) || {};
    var keys = ["facebook", "telegram", "youtube", "tiktok"];
    var wrap = el("div", { class: "social-links" });
    var found = 0;
    keys.forEach(function (key) {
      var url = social[key];
      if (!url) return;
      found += 1;
      wrap.appendChild(
        el("a", {
          href: url,
          target: "_blank",
          rel: "noopener noreferrer",
          "aria-label": "Bonafide International School on " + key,
          title: key.charAt(0).toUpperCase() + key.slice(1),
          html: '<svg viewBox="0 0 16 16" aria-hidden="true">' + (SOCIAL_ICONS[key] || "") + "</svg>"
        })
      );
    });
    return found ? wrap : null;
  }

  function renderFooter() {
    var host = document.getElementById("site-footer");
    if (!host) return;
    var s = settings() || {};
    var year = new Date().getFullYear();
    var social = socialLinks(s);
    host.className = "site-footer";
    host.innerHTML = "";
    host.appendChild(
      el("div", { class: "container" }, [
        el("div", { class: "cols" }, [
          el("div", {}, [
            el("strong", { class: "footer-name", text: s.schoolName || "Bonafide International School" }),
            el("p", { text: s.tagline || "Center of Quality Education" }),
            el("p", { text: "📍 " + (s.address || "Hawassa, Ethiopia") }),
            el("p", { text: "📞 " + (s.phone || "") }),
            el("p", {}, [el("a", { href: "mailto:" + (s.email || ""), text: s.email || "" })])
          ]),
          el("div", {}, [
            el("h3", { text: "Explore" }),
            el("p", {}, [el("a", { href: "index.html", text: "Home" })]),
            el("p", {}, [el("a", { href: "about.html", text: "About us" })]),
            el("p", {}, [el("a", { href: "gallary.html", text: "Gallery" })]),
            el("p", {}, [el("a", { href: "contact-us.html", text: "Contact us" })]),
            el("p", {}, [el("a", { href: "login.html", text: "Staff & student login" })])
          ]),
          el("div", {}, [
            el("h3", { text: "Follow us" }),
            social ||
              el("p", { class: "small muted", text: "No social links configured yet." })
          ])
        ]),
        el("div", { class: "bottom" }, [
          el("span", { text: "© " + year + " " + (s.schoolName || "Bonafide International School") + ". All rights reserved." }),
          el("span", {}, [
            document.createTextNode("Location: "),
            el("a", {
              href: "https://www.google.com/maps/search/?api=1&query=" + encodeURIComponent(s.mapQuery || "Bonafide School, Hawassa, Ethiopia"),
              target: "_blank",
              rel: "noopener noreferrer",
              text: "Open in Maps"
            })
          ])
        ])
      ])
    );
  }

  function toast(message, kind) {
    var stack = document.querySelector(".toast-stack");
    if (!stack) {
      stack = el("div", { class: "toast-stack", role: "status", "aria-live": "polite" });
      document.body.appendChild(stack);
    }
    var node = el("div", { class: "toast " + (kind || ""), text: message });
    stack.appendChild(node);
    setTimeout(function () {
      node.remove();
    }, 4200);
  }

  function initials(name) {
    var parts = String(name || "?")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (!parts.length) return "?";
    return (parts[0][0] + (parts[1] ? parts[1][0] : "")).toUpperCase();
  }

  function avatar(name, photoDataUrl, extraClass) {
    if (photoDataUrl) {
      return el("img", { class: "avatar " + (extraClass || ""), src: photoDataUrl, alt: name || "" });
    }
    return el("div", { class: "avatar " + (extraClass || ""), text: initials(name) });
  }

  function roleBadge(role) {
    var cls = role === "admin" ? "badge-blue" : role === "teacher" ? "badge-green" : "badge-amber";
    return el("span", { class: "badge " + cls, text: role.charAt(0).toUpperCase() + role.slice(1) });
  }

  function statusBadge(status) {
    var cls = status === "Active" ? "badge-green" : status === "Suspended" ? "badge-red" : "badge-grey";
    return el("span", { class: "badge " + cls, text: status });
  }

  function formatDate(iso) {
    if (!iso) return "-";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "-";
    return d.toLocaleDateString("en-GB", { year: "numeric", month: "short", day: "numeric" });
  }

  function formatDateTime(iso) {
    if (!iso) return "-";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "-";
    return d.toLocaleString("en-GB", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  }

  function fileToDataUrl(file, maxWidth) {
    return new Promise(function (resolve, reject) {
      if (!file) return resolve("");
      if (!/^image\//.test(file.type)) return reject(new Error("Please choose an image file."));
      var reader = new FileReader();
      reader.onerror = function () {
        reject(new Error("Could not read that image."));
      };
      reader.onload = function () {
        var dataUrl = String(reader.result || "");
        if (!maxWidth) return resolve(dataUrl);
        var img = new Image();
        img.onload = function () {
          var scale = Math.min(1, maxWidth / img.width);
          var canvas = document.createElement("canvas");
          canvas.width = Math.round(img.width * scale);
          canvas.height = Math.round(img.height * scale);
          canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
          resolve(canvas.toDataURL("image/jpeg", 0.82));
        };
        img.onerror = function () {
          resolve(dataUrl);
        };
        img.src = dataUrl;
      };
      reader.readAsDataURL(file);
    });
  }

  function confirmDialog(message) {
    return window.confirm(message);
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (e) {
        ok = false;
      }
      area.remove();
      ok ? resolve() : reject(new Error("Copy failed"));
    });
  }

  function modal(title, contentNode, actions) {
    var backdrop = el("div", { class: "modal-backdrop" });
    var box = el("div", { class: "modal", role: "dialog", "aria-modal": "true" }, [el("h2", { text: title }), contentNode]);
    (actions || []).forEach(function (action) {
      box.appendChild(
        el("button", {
          class: "btn " + (action.variant ? "btn-" + action.variant : ""),
          type: "button",
          text: action.label,
          onclick: function () {
            if (action.onClick) action.onClick(backdrop);
            else backdrop.remove();
          }
        })
      );
    });
    backdrop.appendChild(box);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop) backdrop.remove();
    });
    document.body.appendChild(backdrop);
    return backdrop;
  }

  function passwordWidget(input, feedbackNode) {
    function render() {
      if (!feedbackNode) return;
      var result = window.BIS.accounts.passwordStrength(input.value);
      var problems = window.BIS.accounts.passwordProblems(input.value);
      var colors = ["var(--danger)", "var(--danger)", "var(--warning)", "var(--success)", "var(--success)", "var(--success)"];
      feedbackNode.innerHTML = "";
      var meter = el("div", { class: "pw-meter" }, [el("i")]);
      meter.firstChild.style.width = (result.score / 5) * 100 + "%";
      meter.firstChild.style.background = colors[result.score];
      feedbackNode.appendChild(meter);
      feedbackNode.appendChild(
        el("div", { class: "hint", text: input.value ? "Strength: " + result.label : "Use 12+ characters with upper, lower, number and symbol." })
      );
      var list = el("ul", { class: "pw-list" });
      [
        ["At least 8 characters", input.value.length >= 8],
        ["12+ characters (recommended)", input.value.length >= 12],
        ["Upper and lower case letters", /[a-z]/.test(input.value) && /[A-Z]/.test(input.value)],
        ["A number", /[0-9]/.test(input.value)],
        ["A symbol", /[^A-Za-z0-9]/.test(input.value)]
      ].forEach(function (item) {
        list.appendChild(el("li", { class: item[1] ? "ok" : "", text: (item[1] ? "✓ " : "• ") + item[0] }));
      });
      feedbackNode.appendChild(list);
      if (input.value && problems.length) {
        feedbackNode.appendChild(el("div", { class: "hint", text: "Blocked: needs " + problems.join(", ") + "." }));
      }
    }
    input.addEventListener("input", render);
    render();
    return render;
  }

  function todayIso() {
    var d = new Date();
    var m = String(d.getMonth() + 1).padStart(2, "0");
    var day = String(d.getDate()).padStart(2, "0");
    return d.getFullYear() + "-" + m + "-" + day;
  }

  window.UI = {
    toast: toast,
    el: el,
    avatar: avatar,
    initials: initials,
    roleBadge: roleBadge,
    statusBadge: statusBadge,
    formatDate: formatDate,
    formatDateTime: formatDateTime,
    fileToDataUrl: fileToDataUrl,
    confirm: confirmDialog,
    copy: copyText,
    modal: modal,
    passwordWidget: passwordWidget,
    todayIso: todayIso,
    LOGO: LOGO
  };

  function boot() {
    var acct = null;
    try {
      acct = window.BIS ? window.BIS.auth.getCurrentAccount() : null;
    } catch (e) {
      acct = null;
    }
    renderHeader(acct);
    renderFooter();
    var title = document.querySelector("[data-role-tagline]");
    if (title && acct) title.textContent = (acct.displayName || acct.username) + " · " + acct.role;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
