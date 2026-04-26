var DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

var apiBaseUrlInput = document.getElementById("apiBaseUrl");
var aiProviderSelect = document.getElementById("aiProvider");
var manualTextInput = document.getElementById("manualText");
var saveSettingsButton = document.getElementById("saveSettingsButton");
var scanButton = document.getElementById("scanButton");
var resultEl = document.getElementById("result");

function storageGet(keys, callback) {
  chrome.storage.local.get(keys, callback);
}

function storageSet(values, callback) {
  chrome.storage.local.set(values, callback || function () {});
}

function sha256(text) {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(function (digest) {
    var bytes = new Uint8Array(digest);
    var parts = [];
    var i;
    for (i = 0; i < bytes.length; i += 1) {
      parts.push(bytes[i].toString(16).padStart(2, "0"));
    }
    return parts.join("");
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function loadSettings() {
  storageGet(["apiBaseUrl", "aiProvider"], function (stored) {
    apiBaseUrlInput.value = stored.apiBaseUrl || DEFAULT_API_BASE_URL;
    aiProviderSelect.value = stored.aiProvider || "auto";
  });
}

function saveSettings(callback) {
  storageSet(
    {
      apiBaseUrl: apiBaseUrlInput.value.trim() || DEFAULT_API_BASE_URL,
      aiProvider: aiProviderSelect.value || "auto"
    },
    callback
  );
}

function analyzeText(text) {
  return new Promise(function (resolve, reject) {
    chrome.runtime.sendMessage({
      type: "ANALYZE_EMAIL",
      text: text
    }, function (response) {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message || "Background scan failed."));
        return;
      }

      if (!response || !response.ok) {
        reject(new Error((response && response.error) || "Background scan failed."));
        return;
      }

      resolve(response.result);
    });
  });
}

function showResult(result) {
  var phrases = Array.isArray(result.suspicious_phrases) ? result.suspicious_phrases.filter(Boolean) : [];
  var score = Number(result.scam_score || 0);
  var confidence = Number(result.confidence || 0);
  var level = result.risk_level || (score > 70 ? "high" : score >= 40 ? "medium" : "low");
  var html = "";

  resultEl.hidden = false;
  html += '<div class="score">' + escapeHtml(level.toUpperCase()) + " risk: " + score + "/100</div>";
  html += "<div>Confidence: " + (confidence || "N/A") + "%</div>";
  html += "<div><strong>Action:</strong> " + escapeHtml(result.recommended_action || "Verify links and sender before acting.") + "</div>";
  html += "<div><strong>Why:</strong> " + escapeHtml(result.explanation || "No explanation returned.") + "</div>";
  if (phrases.length) {
    html += "<div><strong>Suspicious phrases:</strong> " + phrases.map(escapeHtml).join(", ") + "</div>";
  }
  resultEl.innerHTML = html;
}

scanButton.addEventListener("click", function () {
  var text = manualTextInput.value.trim();

  if (!text) {
    resultEl.hidden = false;
    resultEl.textContent = "Paste email text first.";
    return;
  }

  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  resultEl.hidden = false;
  resultEl.textContent = "Checking email...";

  saveSettings(function () {
    sha256(text)
      .then(function (hash) {
        var cacheKey = "analysis:" + (apiBaseUrlInput.value.trim() || DEFAULT_API_BASE_URL) + ":" + (aiProviderSelect.value || "auto") + ":" + hash;
        storageGet([cacheKey], function (cached) {
          if (cached[cacheKey]) {
            showResult(cached[cacheKey]);
            scanButton.disabled = false;
            scanButton.textContent = "Scan pasted text";
            return;
          }

          analyzeText(text)
            .then(function (result) {
              var values = {};
              values[cacheKey] = result;
              storageSet(values, function () {
                showResult(result);
                scanButton.disabled = false;
                scanButton.textContent = "Scan pasted text";
              });
            })
            .catch(function (error) {
              resultEl.textContent = "Scan failed: " + error.message;
              scanButton.disabled = false;
              scanButton.textContent = "Scan pasted text";
            });
        });
      })
      .catch(function (error) {
        resultEl.textContent = "Scan failed: " + error.message;
        scanButton.disabled = false;
        scanButton.textContent = "Scan pasted text";
      });
  });
});

saveSettingsButton.addEventListener("click", function () {
  saveSettings(function () {
    resultEl.hidden = false;
    resultEl.textContent = "Settings saved.";
  });
});

apiBaseUrlInput.addEventListener("change", function () {
  saveSettings();
});

aiProviderSelect.addEventListener("change", function () {
  saveSettings();
});

loadSettings();
