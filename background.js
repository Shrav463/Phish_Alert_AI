var DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
var LOCAL_API_FALLBACKS = [
  "http://127.0.0.1:8000",
  "http://127.0.0.1:8001",
  "http://localhost:8000",
  "http://localhost:8001"
];

chrome.runtime.onInstalled.addListener(function () {
  chrome.storage.local.get(["apiBaseUrl", "aiProvider"], function (stored) {
    if (!stored.apiBaseUrl) {
      chrome.storage.local.set({ apiBaseUrl: DEFAULT_API_BASE_URL });
    }
    if (!stored.aiProvider) {
      chrome.storage.local.set({ aiProvider: "auto" });
    }
  });
});

function getApiBaseUrl(callback) {
  chrome.storage.local.get(["apiBaseUrl"], function (stored) {
    callback(stored.apiBaseUrl || DEFAULT_API_BASE_URL);
  });
}

function getCandidateApiBaseUrls(apiBaseUrl) {
  var normalized = String(apiBaseUrl || "").trim().replace(/\/$/, "");
  if (!normalized) {
    return LOCAL_API_FALLBACKS.slice();
  }
  if (normalized === "http://127.0.0.1:8000") {
    return [
      "http://127.0.0.1:8000",
      "http://127.0.0.1:8001",
      "http://localhost:8000",
      "http://localhost:8001"
    ];
  }
  if (normalized === "http://127.0.0.1:8001") {
    return [
      "http://127.0.0.1:8001",
      "http://127.0.0.1:8000",
      "http://localhost:8001",
      "http://localhost:8000"
    ];
  }
  if (normalized === "http://localhost:8000") {
    return [
      "http://localhost:8000",
      "http://localhost:8001",
      "http://127.0.0.1:8000",
      "http://127.0.0.1:8001"
    ];
  }
  if (normalized === "http://localhost:8001") {
    return [
      "http://localhost:8001",
      "http://localhost:8000",
      "http://127.0.0.1:8001",
      "http://127.0.0.1:8000"
    ];
  }
  return [normalized];
}

function analyzeEmailText(text, done) {
  getApiBaseUrl(function (apiBaseUrl) {
    chrome.storage.local.get(["aiProvider"], function (stored) {
      var aiProvider = stored.aiProvider || "auto";
      var candidates = getCandidateApiBaseUrls(apiBaseUrl);
      var index = 0;

      function tryNext(lastError) {
        var candidateBaseUrl;

        if (index >= candidates.length) {
          done({ ok: false, error: lastError || "Could not reach the scan API." });
          return;
        }

        candidateBaseUrl = candidates[index];
        index += 1;

        fetch(candidateBaseUrl + "/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: text, ai_provider: aiProvider })
        })
          .then(function (response) {
            if (!response.ok) {
              return response.text().then(function (detail) {
                done({
                  ok: false,
                  error: "API returned " + response.status + ": " + detail.slice(0, 180)
                });
              });
            }
            return response.json().then(function (result) {
              if (candidateBaseUrl !== apiBaseUrl) {
                chrome.storage.local.set({ apiBaseUrl: candidateBaseUrl });
              }
              done({ ok: true, result: result });
            });
          })
          .catch(function (error) {
            tryNext(error && error.message ? error.message : "Could not reach the scan API.");
          });
      }

      tryNext("");
    });
  });
}

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message && message.type === "PING") {
    sendResponse({ ok: true, source: "background" });
    return false;
  }

  if (message && message.type === "ANALYZE_EMAIL") {
    analyzeEmailText(String(message.text || ""), sendResponse);
    return true;
  }

  if (!message || message.type !== "HIGH_RISK_EMAIL") {
    return false;
  }

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon128.png",
    title: "High-risk email detected (" + Number(message.score || 0) + "/100)",
    message: String(message.explanation || "Suspicious email detected.").slice(0, 180),
    priority: 2
  });

  sendResponse({ ok: true });
  return true;
});
