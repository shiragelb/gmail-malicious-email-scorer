// Copy to firebase-config.js and fill in values from the Firebase console.
// firebase-config.js is gitignored — never commit real keys that you treat as secret
// (the Firebase web apiKey is public by design; still keep project-specific files local if you prefer).

window.__FIREBASE__ = {
  apiKey: "YOUR_WEB_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  // Public Cloud Run URL of the scorer (no trailing slash). Enables /v1/account/token.
  scorerUrl: "https://gmail-scorer-xxxxx.run.app"
};
