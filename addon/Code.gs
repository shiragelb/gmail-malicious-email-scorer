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
  Suspicious: "#8a5a00",
  Malicious: "#b42318"
};

var MAX_ATTACHMENT_FILES = 5;
var MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
var MAX_ATTACHMENT_TOTAL_BYTES = 10 * 1024 * 1024;
var MAX_UNKNOWN_TYPE_BYTES = 2 * 1024 * 1024;

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
  var body = JSON.stringify(payload);
  var response;
  try {
    var headers = signedHeaders(config, body);
    response = UrlFetchApp.fetch(config.url.replace(/\/$/, "") + "/v1/analyze", {
      method: "post",
      contentType: "application/json",
      headers: headers,
      payload: body,
      muteHttpExceptions: true
    });
  } catch (error) {
    return noticeCard("Scorer unreachable", String(error));
  }

  var status = response.getResponseCode();
  var bodyText = response.getContentText() || "";
  if (status < 200 || status >= 300) {
    return noticeCard("Scorer returned " + status, bodyText.slice(0, 500));
  }

  var result;
  try {
    result = JSON.parse(bodyText);
  } catch (error) {
    return noticeCard("Unexpected response", "The scoring service did not return JSON.");
  }
  return resultCard(result, payload.from_address);
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
  var color = VERDICT_COLOR[verdict] || "#8a5a00";

  var summarySection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<font color="' + color + '"><b>' + score + " / 100 · " + escapeHtml(verdict) + "</b></font>"
    ))
    .addWidget(CardService.newTextParagraph().setText(escapeHtml(result.summary || "")));

  uniqueTexts(result.reasons || [], 2).forEach(function(reason) {
    summarySection.addWidget(CardService.newTextParagraph().setText(
      markForReason(reason) + " " + escapeHtml(reason.text || "")
    ));
  });

  var checksSection = CardService.newCardSection().setHeader("What we checked");
  var checks = result.checks || [];
  if (!checks.length) {
    checksSection.addWidget(CardService.newTextParagraph().setText("No checklist was returned."));
  } else {
    checks.forEach(function(check) {
      checksSection.addWidget(CardService.newTextParagraph().setText(formatCheckLine(check)));
    });
  }

  var adviceSection = CardService.newCardSection();
  uniqueStrings(result.mitigations || [], 2).forEach(function(item) {
    adviceSection.addWidget(CardService.newTextParagraph().setText(escapeHtml(item)));
  });

  var buttons = CardService.newButtonSet()
    .addButton(CardService.newTextButton()
      .setText("Report phishing")
      .setOnClickAction(CardService.newAction().setFunctionName("reportPhishing")))
    .addButton(CardService.newTextButton()
      .setText("Block sender")
      .setOnClickAction(CardService.newAction()
        .setFunctionName("blockSender")
        .setParameters({ fromAddress: fromAddress || "" })));
  adviceSection.addWidget(buttons);

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer").setSubtitle(verdict))
    .addSection(summarySection)
    .addSection(checksSection)
    .addSection(adviceSection)
    .build();
}

function formatCheckLine(check) {
  var status = String((check && check.status) || "pass");
  var mark = checkMark(status);
  var label = escapeHtml((check && check.label) || "Check");
  var detail = escapeHtml((check && check.detail) || "");
  return mark + " <b>" + label + "</b> — " + detail;
}

function checkMark(status) {
  if (status === "fail") {
    return '<font color="#b42318"><b>✕</b></font>';
  }
  if (status === "warn") {
    return '<font color="#8a5a00"><b>!</b></font>';
  }
  if (status === "skip") {
    return '<font color="#5c6b7a">–</font>';
  }
  return '<font color="#0d7a3f"><b>✓</b></font>';
}

function markForReason(reason) {
  var polarity = String((reason && reason.polarity) || "note");
  if (polarity === "risk") {
    return checkMark("fail");
  }
  if (polarity === "trust") {
    return checkMark("pass");
  }
  return checkMark("skip");
}

function noticeCard(title, message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("<b>" + escapeHtml(title) + "</b>"))
      .addWidget(CardService.newTextParagraph().setText(escapeHtml(message || ""))))
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
