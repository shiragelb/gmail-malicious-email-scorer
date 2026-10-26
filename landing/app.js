/**
 * Landing auth. When Firebase is configured (window.__FIREBASE__), sign-in mints
 * a local demo key or calls POST /v1/account/token on the scorer.
 * Without Firebase config, shows setup instructions only.
 */

const cfg = window.__FIREBASE__ || null;
const statusEl = document.getElementById("authStatus");
const tokenPanel = document.getElementById("tokenPanel");
const apiKeyValue = document.getElementById("apiKeyValue");
const signInBtn = document.getElementById("signInBtn");
const copyKeyBtn = document.getElementById("copyKeyBtn");

function showStatus(text, show = true) {
  statusEl.hidden = !show;
  statusEl.textContent = text;
}

function showToken(key) {
  apiKeyValue.textContent = key;
  tokenPanel.hidden = false;
  try {
    localStorage.setItem("mailguard_api_key", key);
  } catch (_) {
    /* ignore quota */
  }
}

signInBtn.addEventListener("click", async () => {
  if (!cfg || !cfg.apiKey || !cfg.authDomain || !cfg.projectId) {
    showStatus(
      "Firebase is not configured yet. After you create a Firebase project, put the web config in landing/firebase-config.js and redeploy Hosting."
    );
    return;
  }
  showStatus("Signing in…");
  try {
    const { initializeApp } = await import("https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js");
    const { getAuth, GoogleAuthProvider, signInWithPopup } = await import(
      "https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js"
    );
    const app = initializeApp(cfg);
    const auth = getAuth(app);
    const result = await signInWithPopup(auth, new GoogleAuthProvider());
    const idToken = await result.user.getIdToken();
    const scorer = (cfg.scorerUrl || "").replace(/\/$/, "");
    if (scorer) {
      const res = await fetch(`${scorer}/v1/account/token`, {
        method: "POST",
        headers: { Authorization: `Bearer ${idToken}`, "Content-Type": "application/json" },
        body: "{}",
      });
      if (!res.ok) {
        throw new Error(`Token endpoint returned ${res.status}`);
      }
      const data = await res.json();
      showToken(data.api_key);
      showStatus(`Signed in as ${result.user.email}`);
      return;
    }
    // Local fallback until /v1/account/token is live: stable key from uid (dev only).
    const fallback = `mg_${result.user.uid.replace(/[^a-zA-Z0-9]/g, "").slice(0, 28)}`;
    showToken(fallback);
    showStatus(
      `Signed in as ${result.user.email}. Add this key to the Cloud Run API_KEYS secret until the token API is enabled.`
    );
  } catch (err) {
    showStatus(String(err.message || err));
  }
});

copyKeyBtn.addEventListener("click", async () => {
  const value = apiKeyValue.textContent || "";
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    copyKeyBtn.textContent = "Copied";
    setTimeout(() => {
      copyKeyBtn.textContent = "Copy";
    }, 1500);
  } catch (_) {
    showStatus("Could not copy — select the key and copy manually.");
  }
});

try {
  const saved = localStorage.getItem("mailguard_api_key");
  if (saved) {
    showToken(saved);
    showStatus("Welcome back — your saved API key is below.", true);
  }
} catch (_) {
  /* ignore */
}
