// VULNERABILITY: Exposed API key in client-side JavaScript
const INTERNAL_API_KEY = "sk_test_1234567890_exposed";

async function loadIssues() {
  try {
    const r = await fetch('/api/issues');
    const data = await r.json();
    console.log('Issue count', data.length, INTERNAL_API_KEY);
  } catch (e) {
    console.error(e);
  }
}
loadIssues();
