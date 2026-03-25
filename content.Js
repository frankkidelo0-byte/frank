var SERVER =
  "https://frank-vapdeq.fly.dev";

var mentalHealthKeywords = [
  "how to kill myself",
  "how to suicide",
  "want to die",
  "end my life",
  "self harm",
  "cut myself",
  "hurt myself",
  "suicide methods",
  "how to hang",
  "overdose pills",
  "i want to die",
  "kill myself",
  "suicidal",
  "self-harm",
  "selfharm"
];

function checkPageContent() {
  var bodyText = document.body ?
    document.body.innerText.toLowerCase() :
    "";
  var titleText =
    document.title.toLowerCase();
  var urlText =
    window.location.href.toLowerCase();

  for (var i = 0;
       i < mentalHealthKeywords.length;
       i++) {
    var kw = mentalHealthKeywords[i];
    if (bodyText.indexOf(kw) !== -1 ||
        titleText.indexOf(kw) !== -1 ||
        urlText.indexOf(kw) !== -1) {
      chrome.runtime.sendMessage({
        type: "mental_health",
        url: window.location.href,
        domain: window.location.hostname,
        keyword: kw
      });
      break;
    }
  }
}

function checkSearchInput() {
  var inputs = document.querySelectorAll(
    "input[type='search'], " +
    "input[name='q'], " +
    "input[name='query'], " +
    "textarea[name='q']"
  );

  inputs.forEach(function(input) {
    input.addEventListener(
      "keydown",
      function(e) {
        if (e.key === "Enter") {
          var val = input.value.toLowerCase();
          for (var i = 0;
               i < mentalHealthKeywords.length;
               i++) {
            var kw = mentalHealthKeywords[i];
            if (val.indexOf(kw) !== -1) {
              chrome.runtime.sendMessage({
                type: "mental_health",
                url: window.location.href,
                domain:
                  window.location.hostname,
                keyword: kw
              });
              break;
            }
          }
        }
      }
    );
  });
}

if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    function() {
      checkPageContent();
      checkSearchInput();
    }
  );
} else {
  checkPageContent();
  checkSearchInput();
}

var observer = new MutationObserver(
  function() {
    checkPageContent();
  }
);

if (document.body) {
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

