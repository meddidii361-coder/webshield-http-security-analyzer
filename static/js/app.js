const $ = (id) => document.getElementById(id);
let latestScan = null;

function setView(view) {
  document.querySelectorAll(".view").forEach(el => el.classList.add("hidden"));
  $(view + "-view").classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.view === view));
  $("crumb").textContent = view === "scanner" ? "Scanner" : "Scan history";
  if (view === "history") loadHistory();
}
document.querySelectorAll(".nav-item").forEach(btn => btn.addEventListener("click", () => setView(btn.dataset.view)));

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function statusCounts(checks) {
  return checks.reduce((a, x) => { a[x.status] = (a[x.status] || 0) + 1; return a; }, {});
}
function renderResult(data) {
  latestScan = data;
  $("empty-state").classList.add("hidden");
  $("results").classList.remove("hidden");
  $("scan-meta").textContent = `${data.final_url}  ·  ${new Date(data.checked_at).toLocaleString()}`;
  const score = data.score.score;
  $("score-value").textContent = score;
  $("score-ring").style.background = `conic-gradient(${score >= 85 ? "#39d69a" : score >= 60 ? "#f2b95e" : "#ff6b78"} ${score * 3.6}deg,#1a2b40 0deg)`;
  const rating = data.score.rating;
  $("rating").textContent = rating;
  $("rating").className = "rating-badge " + (score >= 85 ? "good" : score >= 60 ? "mid" : "");
  $("score-title").textContent = score >= 85 ? "Strong header posture" : score >= 60 ? "Some gaps to address" : "Hardening opportunities found";
  $("score-description").textContent = score >= 85 ? "The inspected headers are mostly configured well. Review recommendations for context." : "Review the findings below and prioritize missing or weak response-header controls.";
  $("score-grade").textContent = rating;
  const counts = statusCounts(data.checks);
  const pass = counts.PASS || 0, warn = counts.WARN || 0, fail = counts.FAIL || 0, total = data.checks.length;
  $("pass-count").textContent = pass; $("warn-count").textContent = warn; $("fail-count").textContent = fail;
  $("pass-bar").style.width = `${pass / total * 100}%`; $("warn-bar").style.width = `${warn / total * 100}%`; $("fail-bar").style.width = `${fail / total * 100}%`;
  $("http-status").textContent = data.status_code; $("https-status").textContent = data.is_https ? "HTTPS" : "HTTP";
  $("findings").innerHTML = data.checks.map(item => `
    <article class="finding">
      <div class="finding-top"><span class="finding-name">${esc(item.header)}</span><span class="status ${esc(item.status)}">${esc(item.status)}</span></div>
      <p class="finding-summary">${esc(item.summary)}</p>
      <div class="recommendation"><b>RECOMMENDATION</b>${esc(item.recommendation)}</div>
    </article>`).join("");
  $("download-txt").onclick = () => window.location.href = `/api/report/${data.scan_id}/txt`;
  $("download-json").onclick = () => window.location.href = `/api/report/${data.scan_id}/json`;
  $("print-report").onclick = () => window.print();
}
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("error-box").classList.add("hidden");
  $("loading").classList.remove("hidden");
  $("scan-state").textContent = "SCAN IN PROGRESS";
  const button = document.querySelector(".scan-button");
  button.disabled = true;
  try {
    const response = await fetch("/api/scan", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({url: $("target-url").value.trim(), timeout: Number($("timeout").value)})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed.");
    renderResult(data);
    $("scan-state").textContent = "SCAN COMPLETED";
  } catch (error) {
    $("error-box").textContent = error.message;
    $("error-box").classList.remove("hidden");
    $("scan-state").textContent = "SCAN FAILED";
  } finally {
    $("loading").classList.add("hidden");
    button.disabled = false;
  }
});
async function loadHistory() {
  const holder = $("history-list");
  try {
    const response = await fetch("/api/history");
    const rows = await response.json();
    if (!rows.length) { holder.innerHTML = '<div class="history-empty">No scans saved yet. Run your first scan to populate this list.</div>'; return; }
    holder.innerHTML = rows.map(row => `
      <div class="history-row">
        <div class="history-target"><b>${esc(row.target)}</b><small>${esc(new Date(row.checked_at).toLocaleString())}</small></div>
        <small>HTTP ${esc(row.http_status)}</small>
        <span class="history-score">${esc(row.score)}/100</span>
        <span class="status ${row.score >= 85 ? "PASS" : row.score >= 60 ? "WARN" : "FAIL"}">${esc(row.rating)}</span>
        <button class="history-open" data-id="${row.id}">VIEW →</button>
      </div>`).join("");
    holder.querySelectorAll(".history-open").forEach(btn => btn.addEventListener("click", async () => {
      const r = await fetch(`/api/history/${btn.dataset.id}`);
      const detail = await r.json();
      const data = detail.result;
      data.scan_id = detail.id;
      setView("scanner");
      renderResult(data);
    }));
  } catch {
    holder.innerHTML = '<div class="history-empty">Could not load scan history.</div>';
  }
}
