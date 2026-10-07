/* Contact page: fills in school details and the offline map. */
(function () {
  "use strict";

  var s = BIS.settings.get();

  function setText(id, value) {
    var node = document.getElementById(id);
    if (node && value) node.textContent = value;
  }

  setText("infoAddress", s.address);
  setText("mapAddress", s.address);
  setText("infoPhone", s.phone);
  setText("infoEmail", s.email);

  var phoneLink = document.getElementById("infoPhone");
  if (phoneLink && s.phone) phoneLink.setAttribute("href", "tel:" + String(s.phone).replace(/[^\d+]/g, ""));

  var mailLink = document.getElementById("infoEmail");
  if (mailLink && s.email) mailLink.setAttribute("href", "mailto:" + s.email);

  var mapImage = document.getElementById("mapImage");
  if (mapImage && s.mapFile) mapImage.setAttribute("src", s.mapFile);

  var mapLink = document.getElementById("mapLink");
  if (mapLink) {
    mapLink.setAttribute(
      "href",
      "https://www.google.com/maps/search/?api=1&query=" + encodeURIComponent(s.mapQuery || "Bonafide School, Hawassa, Ethiopia")
    );
  }
})();
