"use strict";

var HIGH_RISK_THRESHOLD = 70;
var BANNER_ID = "gmail-scam-detector-banner";
var RETRY_DELAY_MS = 1200;
var SCAN_IN_FLIGHT = false;
var LAST_EMAIL_KEY = "";
var ACTIVE_SCAN_KEY = "";
var RETRY_TIMER = null;
var EXTENSION_CONTEXT_VALID = true;
var DEBUG_BADGE_ID = "gmail-scam-detector-debug";
var LAST_VISIBLE_EMAIL_KEY = "";

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function firstText(selectors) {
  var i;
  var el;
  for (i = 0; i < selectors.length; i += 1) {
    el = document.querySelector(selectors[i]);
    if (el && normalizeText(el.textContent)) {
      return normalizeText(el.textContent);
    }
  }
  return "";
}

function firstEmail(selectors) {
  var i;
  var el;
  var email;
  for (i = 0; i < selectors.length; i += 1) {
    el = document.querySelector(selectors[i]);
    if (!el) {
      continue;
    }
    email = normalizeText(el.getAttribute("email")) || normalizeText(el.textContent);
    if (email) {
      return email;
    }
  }
  return "";
}

function getOpenEmail() {
  var bodyEl = document.querySelector(".a3s.aiL") ||
    document.querySelector(".a3s") ||
    document.querySelector(".ii.gt div[dir='ltr']") ||
    document.querySelector(".ii.gt");
  var subject;
  var sender;
  var body;

  if (!bodyEl) {
    return null;
  }

  subject = firstText([
    "h2.hP",
    "h2[data-thread-perm-id]",
    "[role='main'] h2"
  ]);

  sender = firstEmail([
    "span.gD[email]",
    "span[email].gD",
    "span[email]"
  ]);

  body = normalizeText(bodyEl.innerText || bodyEl.textContent);
  if (!body || body.length < 20) {
    return null;
  }

  return {
    subject: subject,
    sender: sender,
    body: body
  };
}

function getEmailKey(email) {
  return [
    email.subject || "",
    email.sender || "",
    email.body.slice(0, 500)
  ].join("|");
}

function buildEmailText(email) {
  return [
    "Subject: " + (email.subject || "(unknown)"),
    "Sender: " + (email.sender || "(unknown)"),
    "",
    email.body
  ].join("\n");
}

function removeBanner() {
  var existing = document.getElementById(BANNER_ID);
  if (existing) {
    existing.remove();
  }
}

function clearUi() {
  removeBanner();
}

function getDebugBadge() {
  var badge = document.getElementById(DEBUG_BADGE_ID);
  if (badge) {
    return badge;
  }

  badge = document.createElement("div");
  badge.id = DEBUG_BADGE_ID;
  badge.style.cssText = [
    "position:fixed",
    "bottom:16px",
    "right:16px",
    "z-index:2147483647",
    "padding:8px 10px",
    "border-radius:10px",
    "background:#111827",
    "color:#ffffff",
    "font:12px Arial,sans-serif",
    "box-shadow:0 8px 24px rgba(0,0,0,0.2)",
    "opacity:0.92",
    "max-width:280px"
  ].join(";");
  document.body.appendChild(badge);
  return badge;
}

function setDebugStatus(message) {
  if (!document.body) {
    return;
  }
  getDebugBadge().textContent = "Scam Detector: " + message;
}

function createBanner(result) {
  var banner = document.createElement("div");
  var score = Number(result.scam_score || 0);
  var confidence = Number(result.confidence || 0);
  var level = result.risk_level || (score > 70 ? "high" : score >= 40 ? "medium" : "low");
  var heading = document.createElement("div");
  var summary = document.createElement("div");
  var why = document.createElement("div");
  var phrases;

  banner.id = BANNER_ID;
  banner.style.cssText = [
    "position:fixed",
    "top:16px",
    "right:16px",
    "z-index:2147483647",
    "width:360px",
    "max-width:calc(100vw - 32px)",
    "padding:14px 16px",
    "border-radius:14px",
    "box-sizing:border-box",
    "font-family:Arial,sans-serif",
    "font-size:13px",
    "line-height:1.45",
    "box-shadow:0 12px 32px rgba(15,23,42,0.18)"
  ].join(";");

  if (score > HIGH_RISK_THRESHOLD) {
    banner.style.cssText += ";background:#fff1f2;border:1px solid #fda4af;color:#881337";
  } else if (score >= 40) {
    banner.style.cssText += ";background:#fffbeb;border:1px solid #fcd34d;color:#92400e";
  } else {
    banner.style.cssText += ";background:#eff6ff;border:1px solid #93c5fd;color:#1d4ed8";
  }

  heading.textContent = "Scam check: " + level + " risk (" + score + "/100)";
  heading.style.cssText = "font-weight:700;font-size:14px;";
  banner.appendChild(heading);

  summary.textContent = (result.recommended_action || "Verify links and sender before acting.") +
    (confidence ? " Confidence: " + confidence + "%." : "");
  summary.style.cssText = "margin-top:4px;";
  banner.appendChild(summary);

  why.textContent = result.explanation || "No explanation returned.";
  why.style.cssText = "margin-top:8px;opacity:0.92;";
  banner.appendChild(why);

  phrases = Array.isArray(result.suspicious_phrases) ? result.suspicious_phrases.filter(Boolean) : [];
  if (phrases.length) {
    var phraseEl = document.createElement("div");
    phraseEl.textContent = "Suspicious phrases: " + phrases.join(", ");
    phraseEl.style.cssText = "margin-top:8px;font-size:12px;opacity:0.86;";
    banner.appendChild(phraseEl);
  }

  return banner;
}

function renderResult(result) {
  var banner = createBanner(result);
  removeBanner();
  document.body.appendChild(banner);
  setDebugStatus("banner shown");
}

function notifyIfHighRisk(result) {
  var score = Number(result && result.scam_score || 0);
  if (score <= HIGH_RISK_THRESHOLD) {
    return;
  }

  chrome.runtime.sendMessage({
    type: "HIGH_RISK_EMAIL",
    score: score,
    explanation: result && result.explanation
  }, function () {
    if (chrome.runtime.lastError) {
      return;
    }
  });
}

function scheduleRetry() {
  if (!EXTENSION_CONTEXT_VALID) {
    return;
  }

  setDebugStatus("retrying scan");
  clearTimeout(RETRY_TIMER);
  RETRY_TIMER = setTimeout(function () {
    analyzeCurrentEmail();
  }, RETRY_DELAY_MS);
}

function invalidateExtensionContext() {
  EXTENSION_CONTEXT_VALID = false;
  SCAN_IN_FLIGHT = false;
  ACTIVE_SCAN_KEY = "";
  clearTimeout(RETRY_TIMER);
  setDebugStatus("extension reloaded; refresh tab");
}

function analyzeCurrentEmail() {
  var email;
  var key;
  var text;

  if (!EXTENSION_CONTEXT_VALID) {
    return;
  }

  if (SCAN_IN_FLIGHT) {
    setDebugStatus("scan in flight");
    return;
  }

  email = getOpenEmail();
  if (!email) {
    LAST_VISIBLE_EMAIL_KEY = "";
    LAST_EMAIL_KEY = "";
    ACTIVE_SCAN_KEY = "";
    clearUi();
    setDebugStatus("waiting for open email");
    return;
  }

  key = getEmailKey(email);
  if (LAST_VISIBLE_EMAIL_KEY && LAST_VISIBLE_EMAIL_KEY !== key) {
    clearUi();
  }
  LAST_VISIBLE_EMAIL_KEY = key;

  if (key === LAST_EMAIL_KEY || key === ACTIVE_SCAN_KEY) {
    setDebugStatus("email already scanned");
    return;
  }

  ACTIVE_SCAN_KEY = key;
  SCAN_IN_FLIGHT = true;
  text = buildEmailText(email);
  setDebugStatus("sending email to backend");

  try {
    chrome.runtime.sendMessage(
      {
        type: "ANALYZE_EMAIL",
        text: text
      },
      function (response) {
        SCAN_IN_FLIGHT = false;
        ACTIVE_SCAN_KEY = "";

        if (chrome.runtime.lastError) {
          if (String(chrome.runtime.lastError.message || "").indexOf("Extension context invalidated") !== -1) {
            invalidateExtensionContext();
            return;
          }
          setDebugStatus("runtime error");
          scheduleRetry();
          return;
        }

        if (!response || !response.ok) {
          setDebugStatus("backend error");
          scheduleRetry();
          return;
        }

        clearTimeout(RETRY_TIMER);
        LAST_EMAIL_KEY = key;
        setDebugStatus("scan result received");
        renderResult(response.result);
        notifyIfHighRisk(response.result);
      }
    );
  } catch (error) {
    if (error && String(error.message || "").indexOf("Extension context invalidated") !== -1) {
      invalidateExtensionContext();
      return;
    }

    SCAN_IN_FLIGHT = false;
    ACTIVE_SCAN_KEY = "";
    setDebugStatus("sendMessage failed");
    scheduleRetry();
  }
}

function debounce(fn, delay) {
  var timer = null;
  return function () {
    clearTimeout(timer);
    timer = setTimeout(fn, delay);
  };
}

var debouncedAnalyze = debounce(analyzeCurrentEmail, 250);

var observer = new MutationObserver(function () {
  debouncedAnalyze();
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});

setInterval(analyzeCurrentEmail, 800);
setDebugStatus("content script loaded");
debouncedAnalyze();
