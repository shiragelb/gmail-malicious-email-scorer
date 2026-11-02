/**
 * Gmail sidebar for the Malicious Email Scorer.
 *
 * Script properties (Project settings > Script properties) — shared for all installers:
 *   BACKEND_URL              Public https URL of the FastAPI service (no trailing slash).
 *   REQUEST_SIGNING_SECRET   Same value as backend REQUEST_SIGNING_SECRET (required in production).
 *
 * User properties (File > Project properties > User properties, or set via setup card) — per Gmail account:
 *   API_KEY                  Your personal token (matches backend API_KEY or an entry in API_KEYS).
 *
 * Apps Script cannot call localhost. Use Cloud Run (or a tunnel) for BACKEND_URL.
 */

var HEADER_NAMES = [
  "Authentication-Results",
  "ARC-Authentication-Results",
  "Received-SPF",
  "Reply-To",
  "Return-Path"
];

var SCHEMA_VERSION = 2;
var MAX_BODY_CHARS = 20000;

var VERDICT_COLOR = {
  Safe: "#0d7a3f",
  Suspicious: "#b45309",
  Malicious: "#b42318"
};

var VERDICT_ICON = {
  Safe: "https://www.gstatic.com/images/icons/material/system/2x/check_circle_googgreen_48dp.png",
  Suspicious: "https://www.gstatic.com/images/icons/material/system/2x/error_googyellow_48dp.png",
  Malicious: "https://www.gstatic.com/images/icons/material/system/2x/cancel_googred_48dp.png"
};

var STATUS_ICON = {
  pass: "https://www.gstatic.com/images/icons/material/system/2x/check_circle_googgreen_48dp.png",
  fail: "https://www.gstatic.com/images/icons/material/system/2x/cancel_googred_48dp.png",
  warn: "https://www.gstatic.com/images/icons/material/system/2x/error_googyellow_48dp.png",
  skip: "https://www.gstatic.com/images/icons/material/system/2x/help_outline_black_48dp.png"
};

var WAIT_ICON = "https://www.gstatic.com/images/icons/material/system/2x/schedule_black_48dp.png";

var MAX_LINK_ROWS = 6;

var MAX_ATTACHMENT_FILES = 5;
var MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
var MAX_ATTACHMENT_TOTAL_BYTES = 10 * 1024 * 1024;
var MAX_UNKNOWN_TYPE_BYTES = 2 * 1024 * 1024;
var DEEP_SCAN_POLLS = 1;
var DEEP_SCAN_WAIT_MS = 500;

// Only these file types are inspected by the backend, so only their bytes leave Gmail.
var INSPECTED_EXTENSIONS = [
  "pdf", "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltm",
  "ppt", "pptx", "pptm", "rtf", "zip"
];
var INSPECTED_CONTENT_TYPES = [
  "application/pdf", "application/zip", "application/x-zip-compressed", "application/msword",
  "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument",
  "application/vnd.ms-office", "application/rtf"
];

function onGmailMessageOpen(event) {
  return buildAnalysisCard(event);
}

function buildAnalysisCard(event) {
  var message = currentMessage(event);
  if (!message) {
    return noticeCard("Message unavailable", "Open a message and try the scorer again.");
  }
  var config = backendConfig();
  if (!config.url) {
    return noticeCard(
      "Backend URL missing",
      "Set the script property BACKEND_URL to the public https address of the scoring service."
    );
  }
  if (!config.key) {
    return noticeCard(
      "API key missing",
      "Open the product site, sign in, copy your API key, then set the User property API_KEY in this Apps Script project."
    );
  }

  var payload = messagePayload(message);
  return fetchAnalysisCard(config, "/v1/analyze", payload, payload.from_address);
}

function requestDeepScan(event) {
  return deepScanWaitCard();
}

function runDeepScan(event) {
  var message = currentMessage(event);
  if (!message) {
    return noticeCard("Message unavailable", "Open the message again before running the reputation check.");
  }
  var config = backendConfig();
  if (!config.url || !config.key) {
    return noticeCard("Scorer is not configured", "Set BACKEND_URL and API_KEY before running an on-demand check.");
  }
  var payload = messagePayload(message);
  var started = postJson(config, "/v1/deep-scan", payload);
  if (started.card) {
    return started.card;
  }
  return settleDeepScan(config, payload, payload.from_address, started.result);
}

function deepScanWaitCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("Checking links")
      .setSubtitle("Usually about 10 seconds")
      .setImageUrl(WAIT_ICON)
      .setImageStyle(CardService.ImageStyle.CIRCLE))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newDecoratedText()
        .setText("Asking other scanners about these links")
        .setBottomLabel("Keep this sidebar open. Gmail will show a spinner until the result arrives.")
        .setStartIcon(CardService.newIconImage().setIconUrl(WAIT_ICON))
        .setWrapText(true))
      .addWidget(CardService.newButtonSet().addButton(
        filledButton("Start scan", spinnerAction("runDeepScan"), VERDICT_COLOR.Safe)
      )))
    .build();
}

function refreshDeepScan(event) {
  var message = currentMessage(event);
  if (!message) {
    return noticeCard("Message unavailable", "Open the message again before checking those links.");
  }
  var scanId = (event.parameters && event.parameters.scanId) || "";
  if (!scanId) {
    return noticeCard("Scan expired", "Tap Check link reputation again from the sidebar.");
  }
  var config = backendConfig();
  if (!config.url || !config.key) {
    return noticeCard("Scorer is not configured", "Set BACKEND_URL and API_KEY before checking those links.");
  }
  var emailPayload = messagePayload(message);
  var started = postJson(config, "/v1/deep-scan/result", {
    scan_id: scanId,
    email: emailPayload
  });
  if (started.card) {
    return started.card;
  }
  return settleDeepScan(config, emailPayload, emailPayload.from_address, started.result);
}

function settleDeepScan(config, emailPayload, fromAddress, result) {
  var n = 0;
  while (
    result &&
    result.deep_scan &&
    result.deep_scan.status === "pending" &&
    result.deep_scan.scan_id &&
    n < DEEP_SCAN_POLLS
  ) {
    Utilities.sleep(DEEP_SCAN_WAIT_MS);
    n += 1;
    var next = postJson(config, "/v1/deep-scan/result", {
      scan_id: String(result.deep_scan.scan_id),
      email: emailPayload
    });
    if (next.card) {
      return next.card;
    }
    result = next.result;
  }
  return resultCard(result, fromAddress);
}

function fetchAnalysisCard(config, path, payload, fromAddress) {
  var posted = postJson(config, path, payload);
  if (posted.card) {
    return posted.card;
  }
  return resultCard(posted.result, fromAddress);
}

function postJson(config, path, payload) {
  var body = JSON.stringify(payload);
  var response;
  try {
    response = UrlFetchApp.fetch(config.url.replace(/\/$/, "") + path, {
      method: "post",
      contentType: "application/json",
      headers: signedHeaders(config, body),
      payload: body,
      muteHttpExceptions: true
    });
  } catch (error) {
    return { card: noticeCard("Scorer unreachable", String(error)) };
  }

  var status = response.getResponseCode();
  var bodyText = response.getContentText() || "";
  if (status < 200 || status >= 300) {
    return { card: noticeCard("Scorer returned " + status, bodyText.slice(0, 500)) };
  }
  try {
    return { result: JSON.parse(bodyText) };
  } catch (error) {
    return { card: noticeCard("Unexpected response", "The scoring service did not return JSON.") };
  }
}

function spinnerAction(functionName, parameters) {
  var action = CardService.newAction()
    .setFunctionName(functionName)
    .setLoadIndicator(CardService.LoadIndicator.SPINNER);
  if (parameters) {
    action.setParameters(parameters);
  }
  return action;
}

function reportPhishing(event) {
  var message = currentMessage(event);
  if (!message) {
    return noticeCard("Message unavailable", "Open the message again before reporting it.");
  }
  message.moveToSpam();
  return noticeCard("Reported as phishing", "This message was moved to Spam.");
}

function blockSender(event) {
  var message = currentMessage(event);
  var fromAddress = (event.parameters && event.parameters.fromAddress) || "";
  if (message) {
    message.moveToTrash();
  }
  var filterNote = "This message was moved to Trash.";
  if (fromAddress) {
    try {
      Gmail.Users.Settings.Filters.create({
        criteria: { from: fromAddress },
        action: { addLabelIds: ["TRASH"], removeLabelIds: ["INBOX"] }
      }, "me");
      filterNote = "Future mail from " + fromAddress + " will be trashed, and this message was moved to Trash.";
    } catch (error) {
      filterNote = "This message was moved to Trash. Creating a lasting filter needs the Gmail API advanced service: " + error;
    }
  }
  return noticeCard("Sender blocked", filterNote);
}

function currentMessage(event) {
  if (!event || !event.gmail || !event.gmail.messageId) {
    return null;
  }
  if (event.gmail.accessToken) {
    GmailApp.setCurrentMessageAccessToken(event.gmail.accessToken);
  }
  return GmailApp.getMessageById(event.gmail.messageId);
}

function backendConfig() {
  var script = PropertiesService.getScriptProperties();
  var user = PropertiesService.getUserProperties();
  // Prefer per-user key; fall back to legacy shared Script property during migration.
  var key = user.getProperty("API_KEY") || script.getProperty("API_KEY") || "";
  return {
    url: script.getProperty("BACKEND_URL") || "",
    key: key,
    signingSecret: script.getProperty("REQUEST_SIGNING_SECRET") || ""
  };
}

function signedHeaders(config, body) {
  var headers = {
    "X-API-Key": config.key
  };
  if (!config.signingSecret) {
    return headers;
  }
  var timestamp = String(Math.floor(new Date().getTime() / 1000));
  var nonce = Utilities.getUuid().replace(/-/g, "") + Utilities.getUuid().replace(/-/g, "").slice(0, 8);
  var bodyHash = bytesToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, body, Utilities.Charset.UTF_8));
  var payload = timestamp + "." + nonce + "." + bodyHash;
  var signature = bytesToHex(
    Utilities.computeHmacSha256Signature(payload, config.signingSecret, Utilities.Charset.UTF_8)
  );
  headers["X-Timestamp"] = timestamp;
  headers["X-Nonce"] = nonce;
  headers["X-Signature"] = signature;
  return headers;
}

function bytesToHex(bytes) {
  var out = [];
  for (var i = 0; i < bytes.length; i++) {
    var value = bytes[i];
    if (value < 0) {
      value += 256;
    }
    var hex = value.toString(16);
    out.push(hex.length === 1 ? "0" + hex : hex);
  }
  return out.join("");
}

function messagePayload(message) {
  var fromRaw = message.getFrom() || "";
  var parsed = parseFrom(fromRaw);
  var headers = {};
  HEADER_NAMES.forEach(function(name) {
    var value = "";
    try {
      value = message.getHeader(name) || "";
    } catch (error) {
      value = "";
    }
    if (value) {
      headers[name] = String(value).slice(0, 20000);
    }
  });
  var attachmentPayload = collectAttachments(message);
  var plain = "";
  var html = "";
  try {
    plain = message.getPlainBody() || "";
  } catch (error) {
    plain = "";
  }
  try {
    // HTML is sent even when a plain body exists: hidden prompt-injection text only lives there.
    // The backend inspects it locally and never forwards it to the language model.
    html = message.getBody() || "";
  } catch (error) {
    html = "";
  }
  return {
    schema_version: SCHEMA_VERSION,
    message_id: message.getId(),
    subject: message.getSubject() || "",
    from_display: parsed.name,
    from_address: parsed.address,
    reply_to: headers["Reply-To"] || "",
    body_text: plain.slice(0, MAX_BODY_CHARS),
    body_html: html.slice(0, MAX_BODY_CHARS),
    headers: headers,
    attachment_names: attachmentPayload.names,
    attachments: attachmentPayload.files
  };
}

function collectAttachments(message) {
  var names = [];
  var files = [];
  var totalBytes = 0;
  var blobs = [];
  try {
    blobs = message.getAttachments({includeInlineImages: false, includeAttachments: true}) || [];
  } catch (error) {
    try {
      blobs = message.getAttachments() || [];
    } catch (inner) {
      blobs = [];
    }
  }
  blobs.slice(0, 50).forEach(function(item) {
    var name = "";
    try {
      name = item.getName() || "";
    } catch (error) {
      name = "";
    }
    if (name) {
      names.push(String(name).slice(0, 300));
    }
    if (files.length >= MAX_ATTACHMENT_FILES) {
      return;
    }
    var size = 0;
    try {
      size = Number(item.getSize() || 0);
    } catch (error) {
      size = 0;
    }
    var contentType = "";
    try {
      contentType = item.getContentType() || "";
    } catch (error) {
      contentType = "";
    }
    var entry = {
      name: String(name || "attachment").slice(0, 300),
      content_type: String(contentType).slice(0, 200),
      size: size,
      content_b64: ""
    };
    var sendBytes = shouldSendBytes(name, contentType, size);
    if (sendBytes && size > 0 && size <= MAX_ATTACHMENT_BYTES && totalBytes + size <= MAX_ATTACHMENT_TOTAL_BYTES) {
      try {
        var bytes = item.getBytes();
        if (bytes && bytes.length && bytes.length <= MAX_ATTACHMENT_BYTES) {
          entry.content_b64 = Utilities.base64Encode(bytes);
          entry.size = bytes.length;
          totalBytes += bytes.length;
        }
      } catch (error) {
        entry.content_b64 = "";
      }
    }
    files.push(entry);
  });
  return { names: names, files: files };
}

function shouldSendBytes(name, contentType, size) {
  var type = String(contentType || "").toLowerCase();
  if (/^(image|audio|video)\//.test(type)) {
    return false;
  }
  var match = /\.([a-z0-9]{1,8})$/.exec(String(name || "").toLowerCase());
  var extension = match ? match[1] : "";
  if (INSPECTED_EXTENSIONS.indexOf(extension) >= 0) {
    return true;
  }
  for (var i = 0; i < INSPECTED_CONTENT_TYPES.length; i++) {
    if (type.indexOf(INSPECTED_CONTENT_TYPES[i]) === 0) {
      return true;
    }
  }
  // Unknown types are sent only when small, so magic-byte checks can catch disguised executables.
  return size > 0 && size <= MAX_UNKNOWN_TYPE_BYTES;
}

function parseFrom(raw) {
  var match = /^(.*)<([^>]+)>$/.exec(raw.trim());
  if (!match) {
    return { name: "", address: raw.trim() };
  }
  return {
    name: match[1].replace(/^"|"$/g, "").trim(),
    address: match[2].trim()
  };
}

function resultCard(result, fromAddress) {
  var verdict = result.verdict || "Suspicious";
  var score = Number(result.score || 0);
  var color = VERDICT_COLOR[verdict] || VERDICT_COLOR.Suspicious;
  var deep = result.deep_scan || {};
  var links = linkEntries(result);

  var header = CardService.newCardHeader()
    .setTitle(verdictTitle(verdict))
    .setSubtitle(score + " out of 100")
    .setImageUrl(VERDICT_ICON[verdict] || VERDICT_ICON.Suspicious)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var summarySection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<font color="' + color + '"><font size="5"><b>' + score + " / 100 · " +
      escapeHtml(verdict) + "</b></font></font>"
    ))
    .addWidget(CardService.newTextParagraph().setText(escapeHtml(result.summary || "")));

  uniqueTexts(result.reasons || [], 2).forEach(function(reason) {
    summarySection.addWidget(
      CardService.newDecoratedText()
        .setText(String(reason.text || ""))
        .setStartIcon(statusIcon(reason.polarity === "risk" ? "fail" : reason.polarity === "trust" ? "pass" : "skip"))
        .setWrapText(true)
    );
  });

  var linksSection = CardService.newCardSection().setHeader("Links in this email");
  if (!links.length) {
    linksSection.addWidget(
      CardService.newDecoratedText()
        .setText("No links")
        .setBottomLabel("Nothing to scan in this message.")
        .setStartIcon(statusIcon("skip"))
        .setWrapText(true)
    );
  } else {
    links.forEach(function(item) {
      linksSection.addWidget(
        CardService.newDecoratedText()
          .setText(item.host)
          .setBottomLabel(item.label)
          .setStartIcon(statusIcon(item.status))
          .setWrapText(true)
          .setOnClickAction(CardService.newAction()
            .setFunctionName("showLinkDetail")
            .setParameters({
              host: item.host,
              status: item.status,
              detail: item.detail
            }))
      );
    });
  }
  if (deep.status === "pending" && deep.scan_id) {
    linksSection.addWidget(
      CardService.newDecoratedText()
        .setText("Scanners did not finish in time")
        .setBottomLabel("The local score still stands. You can try again.")
        .setStartIcon(statusIcon("skip"))
        .setWrapText(true)
    );
  } else if (deep.paused) {
    linksSection.addWidget(
      CardService.newDecoratedText()
        .setText("Reputation checks paused")
        .setBottomLabel("Daily limit reached. The local score still stands.")
        .setStartIcon(statusIcon("skip"))
        .setWrapText(true)
    );
  } else if (deep.available && links.length) {
    linksSection.addWidget(
      CardService.newDecoratedText()
        .setText(deep.reason === "new_domain" ? "New domain — extra scan available" : "Want a second opinion?")
        .setBottomLabel("Ask other scanners about these links. They do not open the pages.")
        .setStartIcon(statusIcon("skip"))
        .setWrapText(true)
    );
  }

  if (deep.status === "pending" && deep.scan_id) {
    linksSection.addWidget(CardService.newButtonSet().addButton(
      filledButton("Keep looking", spinnerAction("refreshDeepScan", { scanId: String(deep.scan_id) }), color)
    ));
  } else if (deep.available) {
    linksSection.addWidget(CardService.newButtonSet().addButton(
      filledButton("Check these links", spinnerAction("requestDeepScan"), color)
    ));
  }

  var checksSection = CardService.newCardSection().setHeader("What we checked");
  var shown = 0;
  (result.checks || []).forEach(function(check) {
    if (!shouldShowCheck(check, links.length > 0)) {
      return;
    }
    shown += 1;
    checksSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(String((check && check.label) || "Check"))
        .setText(checkHeadline(check))
        .setBottomLabel(String((check && check.detail) || ""))
        .setStartIcon(statusIcon((check && check.status) || "pass"))
        .setWrapText(true)
    );
  });
  if (!shown) {
    checksSection.addWidget(CardService.newTextParagraph().setText("No checklist was returned."));
  }

  var adviceSection = CardService.newCardSection().setHeader(verdict === "Safe" ? "Keep in mind" : "What to do");
  if (verdict === "Safe") {
    adviceSection.addWidget(
      CardService.newDecoratedText()
        .setText("This is a guide, not a promise.")
        .setBottomLabel("Still pause if a message asks you to change payment details or open an unexpected file.")
        .setStartIcon(statusIcon("skip"))
        .setWrapText(true)
    );
  } else {
    uniqueStrings(result.mitigations || [], 2).forEach(function(item) {
      adviceSection.addWidget(
        CardService.newDecoratedText()
          .setText(item)
          .setStartIcon(statusIcon(verdict === "Malicious" ? "fail" : "warn"))
          .setWrapText(true)
      );
    });
  }

  var secondary = CardService.newButtonSet();
  var reportBtn = CardService.newTextButton()
    .setText("Report phishing")
    .setOnClickAction(CardService.newAction().setFunctionName("reportPhishing"));
  var blockBtn = CardService.newTextButton()
    .setText("Block sender")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("blockSender")
      .setParameters({ fromAddress: fromAddress || "" }));
  if (verdict === "Malicious" || verdict === "Suspicious") {
    reportBtn.setTextButtonStyle(CardService.TextButtonStyle.FILLED).setBackgroundColor(VERDICT_COLOR.Malicious);
  }
  secondary.addButton(reportBtn).addButton(blockBtn);
  adviceSection.addWidget(secondary);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(summarySection)
    .addSection(linksSection)
    .addSection(checksSection)
    .addSection(adviceSection)
    .build();
}

function showLinkDetail(event) {
  var params = (event && event.parameters) || {};
  var host = String(params.host || "This link");
  var status = String(params.status || "pass");
  var detail = String(params.detail || "Nothing extra was recorded for this address.");
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(host)
      .setSubtitle(linkStatusTitle(status))
      .setImageUrl(VERDICT_ICON[status === "fail" ? "Malicious" : status === "warn" ? "Suspicious" : "Safe"])
      .setImageStyle(CardService.ImageStyle.CIRCLE))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newDecoratedText()
        .setTopLabel(linkStatusTitle(status))
        .setText(host)
        .setBottomLabel(detail)
        .setStartIcon(statusIcon(status))
        .setWrapText(true))
      .addWidget(CardService.newTextParagraph().setText(
        "The scorer never opens this address, so a bad page cannot load on your computer."
      )))
    .build();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

function filledButton(label, action, color) {
  return CardService.newTextButton()
    .setText(label)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setBackgroundColor(color || "#1c2430")
    .setOnClickAction(action);
}

function verdictTitle(verdict) {
  if (verdict === "Safe") {
    return "Looks safe";
  }
  if (verdict === "Malicious") {
    return "Looks malicious";
  }
  return "Looks suspicious";
}

function linkEntries(result) {
  var urls = ((((result || {}).layers || {}).urls || {}).extracted) || [];
  var matches = ((((result || {}).layers || {}).urls || {}).matches) || [];
  var seen = {};
  var rows = [];
  urls.forEach(function(raw) {
    var host = hostOf(raw);
    if (!host || seen[host] || rows.length >= MAX_LINK_ROWS) {
      return;
    }
    seen[host] = true;
    var hit = null;
    for (var i = 0; i < matches.length; i++) {
      var matchUrl = String((matches[i] && matches[i].url) || "");
      if (hostOf(matchUrl) === host || String(matchUrl).toLowerCase().indexOf(host) >= 0) {
        hit = matches[i];
        break;
      }
    }
    var status = "pass";
    var detail = "Nothing flagged this address.";
    var label = "Clear — nothing flagged";
    if (hit) {
      status = hit.confirmed === false ? "warn" : "fail";
      detail = String(hit.detail || hit.threat || "Flagged by a threat list.").slice(0, 180);
      label = hit.confirmed === false ? "Worth a closer look" : "Flagged — do not tap";
    }
    rows.push({ host: host, status: status, detail: detail, label: label });
  });
  return rows;
}

function hostOf(url) {
  var match = String(url || "").match(/^https?:\/\/([^\/?#]+)/i);
  if (!match) {
    return "";
  }
  return match[1].toLowerCase().replace(/^www\./, "").slice(0, 48);
}

function shouldShowCheck(check, hasLinkRows) {
  var id = String((check && check.id) || "");
  var status = String((check && check.status) || "");
  if (id === "pictures" && status === "skip") {
    return false;
  }
  if (id === "files" && status === "skip") {
    return false;
  }
  if (id === "links" && hasLinkRows) {
    return false;
  }
  return true;
}

function checkHeadline(check) {
  var status = String((check && check.status) || "pass");
  if (status === "fail") {
    return "Flagged";
  }
  if (status === "warn") {
    return "Needs a closer look";
  }
  if (status === "skip") {
    return "Not checked";
  }
  return "Passed";
}

function linkStatusTitle(status) {
  if (status === "fail") {
    return "Flagged";
  }
  if (status === "warn") {
    return "Needs a closer look";
  }
  return "Passed";
}

function statusIcon(status) {
  var key = "pass";
  if (status === "fail" || status === "warn" || status === "skip") {
    key = status;
  }
  return CardService.newIconImage().setIconUrl(STATUS_ICON[key] || STATUS_ICON.pass);
}

function noticeCard(title, message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(title || "Malicious Email Scorer")
      .setSubtitle("Malicious Email Scorer")
      .setImageUrl(VERDICT_ICON.Suspicious)
      .setImageStyle(CardService.ImageStyle.CIRCLE))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newDecoratedText()
        .setText(title || "Notice")
        .setBottomLabel(message || "")
        .setStartIcon(statusIcon("warn"))
        .setWrapText(true)))
    .build();
}

function uniqueTexts(items, limit) {
  var seen = [];
  var out = [];
  (items || []).forEach(function(item) {
    var text = String((item && item.text) || "").trim();
    if (!text || out.length >= limit) {
      return;
    }
    var norm = text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    for (var i = 0; i < seen.length; i++) {
      if (norm.indexOf(seen[i]) >= 0 || seen[i].indexOf(norm) >= 0) {
        return;
      }
    }
    seen.push(norm);
    out.push(item);
  });
  return out;
}

function uniqueStrings(items, limit) {
  return uniqueTexts((items || []).map(function(text) {
    return { text: text };
  }), limit).map(function(item) {
    return item.text;
  });
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
