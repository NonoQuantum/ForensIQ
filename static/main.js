// ── Language toggle ──
// Switches every element that has data-en / data-ar attributes.
// Also flips the page direction (ltr/rtl) and remembers the choice.
function toggleLang(forceAr) {
  const html    = document.documentElement;
  const toggle  = document.getElementById("lang-toggle");
  const current = html.getAttribute("lang");
  const goAr    = forceAr === true ? true : current !== "ar";

  html.setAttribute("lang", goAr ? "ar" : "en");
  html.setAttribute("dir",  goAr ? "rtl" : "ltr");
  if (toggle) toggle.textContent = goAr ? "English" : "العربية";

  // Update every element that has data-en and data-ar
  document.querySelectorAll("[data-en]").forEach(function (el) {
    el.textContent = goAr ? el.dataset.ar : el.dataset.en;
  });

  // Update input placeholders separately (they're attributes not text)
  document.querySelectorAll("[data-placeholder-ar]").forEach(function (el) {
    el.placeholder = goAr ? el.dataset.placeholderAr : el.dataset.placeholderEn;
  });

  // Save preference so it persists across pages
  localStorage.setItem("lang", goAr ? "ar" : "en");
}

document.addEventListener("DOMContentLoaded", function () {

  const fileInput = document.getElementById("chat_file");
  const fileName  = document.getElementById("file-name");
  const fileDrop  = document.getElementById("file-drop");
  const form      = document.querySelector(".upload-form");
  const submitBtn = document.getElementById("submit-btn");

  // Update filename label when user picks a file
  if (fileInput) {
    fileInput.addEventListener("change", function () {
      if (fileInput.files.length > 0) {
        fileName.textContent = fileInput.files[0].name;
        fileName.classList.add("chosen");
      }
    });
  }

  // Drag and drop
  if (fileDrop) {
    fileDrop.addEventListener("dragover", function (e) {
      e.preventDefault();
      fileDrop.classList.add("drag-over");
    });

    fileDrop.addEventListener("dragleave", function () {
      fileDrop.classList.remove("drag-over");
    });

    fileDrop.addEventListener("drop", function (e) {
      e.preventDefault();
      fileDrop.classList.remove("drag-over");

      const dropped = e.dataTransfer.files[0];
      if (!dropped) return;

      if (!dropped.name.toLowerCase().endsWith(".txt")) {
        alert("Please drop a .txt file exported from WhatsApp.");
        return;
      }

      const dt = new DataTransfer();
      dt.items.add(dropped);
      fileInput.files = dt.files;

      fileName.textContent = dropped.name;
      fileName.classList.add("chosen");
    });
  }

  // Disable button on submit to prevent double-click
  if (form) {
    form.addEventListener("submit", function () {
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Analysing…";
      }
    });
  }

});
