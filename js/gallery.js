/* Gallery with category filter and lightbox. */
(function () {
  "use strict";

  var SECTIONS = [
    {
      title: "Founder",
      category: "people",
      items: [{ src: "f.jpg", caption: "Argawu Gugsa", sub: "Founder & Visionary Leader" }]
    },
    {
      title: "Academic staff",
      category: "people",
      items: [
        { src: "desta.jpg", caption: "Mr. Desta Kebede", sub: "Managing Director" },
        { src: "negu.jpg", caption: "Mr. Negash Bekele", sub: "Secondary School Principal" },
        { src: "wonde.jpg", caption: "Mr. Wondimagegn Worku", sub: "Primary School Principal" },
        { src: "fre.jpg", caption: "Firehiwot Kebede", sub: "KG Directress" },
        { src: "shime.jpg", caption: "Mr. Shimelis", sub: "Deputy Director" },
        { src: "semu.jpg", caption: "Mr. Semunigus G/Giorgis", sub: "Administration and Finance Head" }
      ]
    },
    {
      title: "Department heads",
      category: "people",
      items: [
        { src: "01.jpg", caption: "Mr. Markos Medhin", sub: "English Department Head" },
        { src: "02.jpg", caption: "Mr. Amde Girma", sub: "Mathematics Department Head" },
        { src: "03.png", caption: "Mr. Yohannes Kutaye", sub: "IT Admin & ICT Department Head" },
        { src: "04.jpg", caption: "Mr. Kibret Ayuba", sub: "Science Department Head" },
        { src: "05.jpg", caption: "Mr. Biruk Tesfaye", sub: "Aesthetics & Sport Science Head" },
        { src: "004.jpg", caption: "Mr. Abreham", sub: "Amharic Department Head" }
      ]
    },
    {
      title: "Technical advisors",
      category: "people",
      items: [
        { src: "001.jpg", caption: "Mr. Firew Bekele", sub: "Technical Advisor" },
        { src: "002.jpg", caption: "Mr. Yimer Asfawu", sub: "Technical Advisor" }
      ]
    },
    {
      title: "Kindergarten",
      category: "kg",
      items: [
        { src: "w.jpg", caption: "Lineup", sub: "Students in the lineup" },
        { src: "e.jpg", caption: "Dining room", sub: "Students in the dining room" },
        { src: "q.jpg", caption: "Play area", sub: "Kids playing" },
        { src: "t.jpg", caption: "Lineup", sub: "Students in the lineup" },
        { src: "r.jpg", caption: "Play area", sub: "Play-based learning" }
      ]
    },
    {
      title: "Primary school",
      category: "primary",
      items: [
        { src: "bonael1.jpg", caption: "Classroom", sub: "Students in class" },
        { src: "bonael2.jpg", caption: "Lineup", sub: "Students at lineup" },
        { src: "el3.jpg", caption: "Classroom", sub: "Students learning" },
        { src: "el4.jpg", caption: "Lunch break", sub: "Students enjoying lunch" },
        { src: "el5.jpg", caption: "Dining room", sub: "Students eating" }
      ]
    },
    {
      title: "High school",
      category: "high",
      items: [
        { src: "lib1.jpg", caption: "Classroom 1", sub: "Secondary learning" },
        { src: "lib2.jpg", caption: "Classroom 2", sub: "Secondary learning" },
        { src: "lib7.jpg", caption: "Classroom 3", sub: "Secondary learning" },
        { src: "lib6.jpg", caption: "Classroom 4", sub: "Secondary learning" }
      ]
    },
    {
      title: "Library",
      category: "library",
      items: [
        { src: "lib4.jpg", caption: "Computers", sub: "Reading & research" },
        { src: "lib3.jpg", caption: "Reading time", sub: "Students" },
        { src: "lib5.jpg", caption: "Team work", sub: "Discussion" },
        { src: "lib01.jpg", caption: "Readers", sub: "Study" }
      ]
    },
    {
      title: "Facilities",
      category: "facilities",
      items: [
        { src: "classroom.jpg", caption: "Classrooms", sub: "Student-centred learning environment" },
        { src: "slab.jpg", caption: "Science lab", sub: "Biology, chemistry and physics" },
        { src: "ictlab.jpg", caption: "ICT lab", sub: "Coding and programming" },
        { src: "art.jpg", caption: "Art room", sub: "Creativity and self-expression" },
        { src: "music.jpg", caption: "Music room", sub: "Hands-on learning activities" },
        { src: "sport.jpg", caption: "Sports field", sub: "Fitness and sportsmanship" },
        { src: "2.jpg", caption: "School life", sub: "Learning together" },
        { src: "3.jpg", caption: "Our students", sub: "A community of learners" },
        { src: "photo_5976608732718679997_y.jpg", caption: "School life", sub: "A moment at Bonafide" },
        { src: "photo_6041779196373617210_y.jpg", caption: "Our students", sub: "A moment at Bonafide" }
      ]
    }
  ];

  var FILTERS = [
    { key: "all", label: "Everything" },
    { key: "people", label: "Staff & founder" },
    { key: "kg", label: "Kindergarten" },
    { key: "primary", label: "Primary" },
    { key: "high", label: "High school" },
    { key: "library", label: "Library" },
    { key: "facilities", label: "Facilities" }
  ];

  var gallery = document.getElementById("gallery");
  var filters = document.getElementById("filters");
  var active = "all";

  function openLightbox(item) {
    var box = UI.el("div", { class: "lightbox" });
    var close = UI.el("button", { class: "close", type: "button", "aria-label": "Close", text: "✕" });
    var img = UI.el("img", { src: item.src, alt: item.caption || "" });
    var cap = UI.el("div", { class: "cap", text: (item.caption ? item.caption + " — " : "") + (item.sub || "") });
    box.appendChild(close);
    box.appendChild(img);
    box.appendChild(cap);
    function dismiss() {
      box.remove();
      document.removeEventListener("keydown", onKey);
    }
    function onKey(e) {
      if (e.key === "Escape") dismiss();
    }
    close.addEventListener("click", dismiss);
    box.addEventListener("click", function (e) {
      if (e.target === box) dismiss();
    });
    document.addEventListener("keydown", onKey);
    document.body.appendChild(box);
  }

  function render() {
    gallery.innerHTML = "";
    SECTIONS.filter(function (section) {
      return active === "all" || section.category === active;
    }).forEach(function (section) {
      gallery.appendChild(UI.el("h2", { text: section.title }));
      var grid = UI.el("div", { class: "gallery-grid", style: "margin:14px 0 30px" });
      section.items.forEach(function (item) {
        var isPerson = Boolean(item.sub) && section.category === "people";
        var figure = UI.el("figure", { class: isPerson ? "person" : "" });
        var button = UI.el("button", { type: "button", "aria-label": "View " + (item.caption || "photo"), onclick: function () { openLightbox(item); } });
        button.appendChild(UI.el("img", { src: item.src, alt: item.caption || "", loading: "lazy" }));
        figure.appendChild(button);
        if (item.caption) figure.appendChild(UI.el("div", { class: "caption", text: item.caption }));
        if (item.sub) figure.appendChild(UI.el("div", { class: "subcaption", text: item.sub }));
        grid.appendChild(figure);
      });
      gallery.appendChild(grid);
    });

    Array.prototype.forEach.call(filters.querySelectorAll("button"), function (btn) {
      btn.setAttribute("aria-pressed", btn.dataset.key === active ? "true" : "false");
    });
  }

  FILTERS.forEach(function (filter) {
    filters.appendChild(
      UI.el("button", {
        type: "button",
        text: filter.label,
        "aria-pressed": "false",
        dataset: { key: filter.key },
        onclick: function () {
          active = filter.key;
          render();
        }
      })
    );
  });

  render();
})();
