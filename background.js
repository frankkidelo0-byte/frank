const SERVER = "https://frank-vapdeq.fly.dev";
const REPORT_URL = SERVER + "/api/client-report";
const RULES_URL = SERVER + "/api/client-rules";

let rules = {
  blocked_domains: [],
  allowed_domains: [],
  mental_health_keywords: [],
  mental_health_domains: [],
  block_page: SERVER + "/blocked"
};

let deviceID = "";
let studentID = "";

function generateDeviceID() {
  return "dev-" + Math.random()
    .toString(36).substr(2, 9);
}

function getOS() {
  var ua = navigator.userAgent;
  if (ua.indexOf("Win") !== -1)
    return "Windows";
  if (ua.indexOf("Mac") !== -1)
    return "MacOS";
  if (ua.indexOf("Linux") !== -1)
    return "Linux";
  if (ua.indexOf("CrOS") !== -1)
    return "ChromeOS";
  return "Unknown";
}

chrome.storage.local.get(
  ["deviceID", "studentID"],
  function(result) {
    if (result.deviceID) {
      deviceID = result.deviceID;
    } else {
      deviceID = generateDeviceID();
      chrome.storage.local.set(
        {deviceID: deviceID});
    }
    if (result.studentID) {
      studentID = result.studentID;
    }
  }
);

function fetchRules() {
  fetch(RULES_URL)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      rules = data;
      chrome.storage.local.set(
        {rules: rules});
      console.log(
        "[AeroShield] Rules updated");
    })
    .catch(function(e) {
      chrome.storage.local.get(
        ["rules"],
        function(result) {
          if (result.rules) {
            rules = result.rules;
          }
        }
      );
    });
}

fetchRules();

chrome.alarms.create("fetchRules",
  {periodInMinutes: 5});

chrome.alarms.onAlarm.addListener(
  function(alarm) {
    if (alarm.name === "fetchRules") {
      fetchRules();
    }
  }
);

function sendReport(report) {
  report.device_id = deviceID;
  report.student_id = studentID;
  report.os = getOS();
  report.browser = "Chrome";
  report.timestamp = new Date()
    .toISOString();

  fetch(REPORT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(report)
  }).catch(function(e) {
    console.log(
      "[AeroShield] Report failed:", e);
  });
}

function isDomainBlocked(hostname) {
  if (!rules.blocked_domains) return false;
  for (var i = 0;
       i < rules.blocked_domains.length;
       i++) {
    var bd = rules.blocked_domains[i]
      .toLowerCase();
    if (hostname === bd ||
        hostname.endsWith("." + bd)) {
      return true;
    }
  }
  return false;
}

function isMentalHealthDomain(hostname) {
  if (!rules.mental_health_domains)
    return false;
  for (var i = 0;
       i < rules.mental_health_domains.length;
       i++) {
    var mhd = rules.mental_health_domains[i]
      

      .toLowerCase();
    if (hostname === mhd ||
        hostname.endsWith("." + mhd)) {
      return true;
    }
  }
  return false;
}

function checkMentalHealthKeywords(text) {
  if (!rules.mental_health_keywords)
    return null;
  var lowerText = text.toLowerCase();
  for (var i = 0;
       i < rules.mental_health_keywords.length;
       i++) {
    var kw = rules.mental_health_keywords[i]
      .toLowerCase();
    if (lowerText.indexOf(kw) !== -1) {
      return kw;
    }
  }
  return null;
}

chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    try {
      var url = new URL(details.url);
      var hostname = url.hostname.toLowerCase();

      if (isMentalHealthDomain(hostname)) {
        sendReport({
          url: details.url,
          domain: hostname,
          keyword: hostname,
          alert_type: "mental_health",
          severity: "critical",
          blocked: true
        });
        return {
          redirectUrl: rules.block_page +
            "?site=" + hostname +
            "&reason=Mental+Health+Safety" +
            "&category=Mental+Health"
        };
      }

      if (isDomainBlocked(hostname)) {
        sendReport({
          url: details.url,
          domain: hostname,
          keyword: hostname,
          alert_type: "blocked_domain",
          severity: "high",
          blocked: true
        });
        return {
          redirectUrl: rules.block_page +
            "?site=" + hostname +
            "&reason=Blocked+Domain" +
            "&category=Policy+Violation"
        };
      }
    } catch(e) {}
    return {};
  },
  {urls: ["<all_urls>"]},
  ["blocking"]
);

chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    try {
      var url = new URL(details.url);
      var hostname = url.hostname.toLowerCase();
      var fullUrl = details.url.toLowerCase();

      var keyword =
        checkMentalHealthKeywords(fullUrl);
      if (!keyword) {
        keyword =
          checkMentalHealthKeywords(hostname);
      }

      if (keyword) {
        sendReport({
          url: details.url,
          domain: hostname,
          keyword: keyword,
          alert_type: "mental_health",
          severity: "critical",
          blocked: true
        });
        return {
          redirectUrl: rules.block_page +
            "?site=" + hostname +
            "&reason=Mental+Health+Safety" +
            "&category=Mental+Health+Alert"
        };
      }
    } catch(e) {}
    return {};
  },
  {
    urls: [
      "*://www.google.com/search*",
      "*://www.bing.com/search*",
      "*://search.yahoo.com/search*",
      "*://duckduckgo.com/*"
    ]
  },
  ["blocking"]
);

chrome.tabs.onUpdated.addListener(
  function(tabId, changeInfo, tab) {
    if (changeInfo.status === "complete" &&
        tab.url) {
      try {
        var url = new URL(tab.url);
        var hostname =
          url.hostname.toLowerCase();

        sendReport({
          url: tab.url,
          domain: hostname,
          title: tab.title || "",
          keyword: "",
          alert_type: "page_visit",
          severity: "low",
          blocked: false
        });
      } catch(e) {}
    }
  }
);

chrome.runtime.onMessage.addListener(
  function(message, sender, sendResponse) {
    if (message.type === "mental_health") {
      sendReport({
        url: message.url,
        domain: message.domain,
        keyword: message.keyword,
        alert_type: "mental_health",
        severity: "critical",
        blocked: false
      });

      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon48.png",
        title: "⚠️ AeroShield Alert",
        message: "Mental health content " +
          "detected. Support is available."
      });
    }

    if (message.type === "set_student") {
      studentID = message.studentID;
      chrome.storage.local.set(
        {studentID: studentID});
      sendResponse({status: "ok"});
    }

    if (message.type === "get_status") {
      sendResponse({
        deviceID: deviceID,
        studentID: studentID,
        rulesLoaded: rules.blocked_domains
          ? rules.blocked_domains.length
          : 0,
        server: SERVER
      });
    }
  }
);

