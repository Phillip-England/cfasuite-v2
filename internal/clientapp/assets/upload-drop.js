(function () {
  function setInputFiles(input, files) {
    if (!files || files.length === 0) return;
    try {
      var dt = new DataTransfer();
      for (var i = 0; i < files.length; i += 1) {
        dt.items.add(files[i]);
      }
      input.files = dt.files;
    } catch (err) {
      return;
    }
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fileNames(files) {
    if (!files || files.length === 0) return "";
    var names = [];
    for (var i = 0; i < files.length; i += 1) {
      names.push(files[i].name);
    }
    return names.join(", ");
  }

  function updateZoneText(input, textEl) {
    var names = fileNames(input.files);
    if (names) {
      textEl.textContent = names;
      return;
    }
    textEl.textContent = "Drag and drop a file here, or click to browse";
  }

  function enhanceFileInput(input) {
    if (!input || input.dataset.dropEnhanced === "1") return;
    if (input.closest(".file-dropzone")) {
      input.dataset.dropEnhanced = "1";
      return;
    }

    var zone = document.createElement("div");
    zone.className = "file-dropzone";
    zone.tabIndex = 0;

    var title = document.createElement("div");
    title.className = "file-dropzone-title";
    title.textContent = "Drop file";

    var text = document.createElement("div");
    text.className = "file-dropzone-text";
    text.textContent = "Drag and drop a file here, or click to browse";

    input.parentNode.insertBefore(zone, input);
    zone.appendChild(title);
    zone.appendChild(text);
    zone.appendChild(input);
    input.classList.add("file-dropzone-input");
    input.dataset.dropEnhanced = "1";

    var openPicker = function () { input.click(); };
    zone.addEventListener("click", function (event) {
      if (event.target === input) return;
      openPicker();
    });
    zone.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openPicker();
      }
    });
    zone.addEventListener("dragenter", function (event) {
      event.preventDefault();
      zone.classList.add("is-dragging");
    });
    zone.addEventListener("dragover", function (event) {
      event.preventDefault();
      zone.classList.add("is-dragging");
    });
    zone.addEventListener("dragleave", function (event) {
      if (!zone.contains(event.relatedTarget)) {
        zone.classList.remove("is-dragging");
      }
    });
    zone.addEventListener("drop", function (event) {
      event.preventDefault();
      zone.classList.remove("is-dragging");
      var files = event.dataTransfer && event.dataTransfer.files ? event.dataTransfer.files : null;
      setInputFiles(input, files);
    });

    input.addEventListener("change", function () {
      updateZoneText(input, text);
    });
    updateZoneText(input, text);
  }

  function enhanceAll(root) {
    var scope = root || document;
    var inputs = scope.querySelectorAll('input[type="file"]');
    for (var i = 0; i < inputs.length; i += 1) {
      enhanceFileInput(inputs[i]);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { enhanceAll(document); });
  } else {
    enhanceAll(document);
  }

  var observer = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i += 1) {
      var record = mutations[i];
      for (var j = 0; j < record.addedNodes.length; j += 1) {
        var node = record.addedNodes[j];
        if (!node || node.nodeType !== 1) continue;
        if (node.matches && node.matches('input[type="file"]')) {
          enhanceFileInput(node);
        } else {
          enhanceAll(node);
        }
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
