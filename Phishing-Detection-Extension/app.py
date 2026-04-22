from datetime import datetime
from functools import wraps
import os
import uuid
from urllib.parse import urlparse

from flask import Flask, jsonify, request, session, send_from_directory, Response
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from db import db, User, Report, ReportVote, BusinessVerificationRequest

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scanlogs.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

CORS(app, supports_credentials=True)
db.init_app(app)


def normalize_domain(value):
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return parsed.netloc.lower().lstrip("www.")
    return value.lstrip("www.")


def normalize_url(value):
    value = (value or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Login required"}), 401
        return fn(user, *args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(user, *args, **kwargs):
            if user.role not in roles:
                return jsonify({"error": "Access denied"}), 403
            return fn(user, *args, **kwargs)

        return wrapper

    return decorator


def is_verified_business_domain(domain):
    req = BusinessVerificationRequest.query.filter_by(
        website_domain=domain,
        status="approved",
    ).first()
    return req is not None


def compute_report_counts(report):
    phishing_votes = sum(1 for vote in report.votes if vote.vote == "phishing")
    non_phishing_votes = sum(1 for vote in report.votes if vote.vote == "non_phishing")
    return phishing_votes, non_phishing_votes


def report_to_public_dict(report):
    phishing_votes, non_phishing_votes = compute_report_counts(report)
    verified = is_verified_business_domain(report.domain)
    verdict = "Undecided"
    if not verified:
        if phishing_votes > non_phishing_votes:
            verdict = "Likely phishing"
        elif non_phishing_votes > phishing_votes:
            verdict = "Likely non-phishing"
    else:
        verdict = "Hidden for verified business"

    data = report.to_dict()
    data.update(
        {
            "phishing_votes": phishing_votes,
            "non_phishing_votes": non_phishing_votes,
            "community_verdict": verdict,
            "verified_business": verified,
        }
    )
    return data


def bootstrap_admin():
    admin = User.query.filter_by(role="admin").first()
    if admin:
        return admin
    admin = User(
        username="admin",
        email="admin@local",
        password_hash=generate_password_hash("admin123"),
        role="admin",
    )
    db.session.add(admin)
    db.session.commit()
    print("Seeded admin login: username=admin password=admin123")
    return admin


def bootstrap_extension_reporter():
    reporter = User.query.filter_by(username="extension_reporter").first()
    if reporter:
        return reporter
    reporter = User(
        username="extension_reporter",
        email="extension_reporter@local",
        password_hash=generate_password_hash(uuid.uuid4().hex),
        role="user",
    )
    db.session.add(reporter)
    db.session.commit()
    return reporter


TOP_VERIFIED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "wikipedia.org", "twitter.com", "x.com", "reddit.com", "yahoo.com",
    "amazon.com", "amazon.in", "netflix.com", "microsoft.com", "office.com",
    "live.com", "bing.com", "apple.com", "icloud.com", "linkedin.com",
    "github.com", "stackoverflow.com", "chatgpt.com", "openai.com", "adobe.com",
    "canva.com", "pinterest.com", "quora.com", "imdb.com", "bbc.com",
    "cnn.com", "nytimes.com", "guardian.com", "forbes.com", "wsj.com",
    "hulu.com", "disneyplus.com", "spotify.com", "soundcloud.com", "twitch.tv",
    "discord.com", "telegram.org", "zoom.us", "slack.com", "dropbox.com",
    "drive.google.com", "docs.google.com", "mail.google.com", "paypal.com", "stripe.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com", "citi.com",
    "salesforce.com", "shopify.com", "ebay.com", "etsy.com", "target.com",
    "walmart.com", "bestbuy.com", "flipkart.com", "aliexpress.com", "taobao.com",
    "baidu.com", "yandex.com", "vk.com", "ok.ru", "naver.com",
    "daum.net", "rakuten.co.jp", "booking.com", "airbnb.com", "tripadvisor.com",
    "uber.com", "lyft.com", "doordash.com", "zomato.com", "swiggy.com",
    "coursera.org", "udemy.com", "khanacademy.org", "edx.org", "mit.edu",
    "stanford.edu", "harvard.edu", "nasa.gov", "whitehouse.gov", "irs.gov",
    "who.int", "un.org", "europa.eu", "weather.com", "accuweather.com",
    "intuit.com", "notion.so", "figma.com", "atlassian.com", "cloudflare.com",
]


def bootstrap_top_verified_domains(admin_user, limit=100):
    domains = [normalize_domain(d) for d in TOP_VERIFIED_DOMAINS[:limit] if normalize_domain(d)]

    now = datetime.utcnow()
    changed = 0
    for domain in domains:
        existing = BusinessVerificationRequest.query.filter_by(website_domain=domain).first()
        if not existing:
            db.session.add(
                BusinessVerificationRequest(
                    business_user_id=admin_user.id,
                    website_domain=domain,
                    business_name=f"Top site: {domain}",
                    proof_details="Auto-seeded from top websites list",
                    status="approved",
                    reviewed_by_admin_id=admin_user.id,
                    review_note="System-approved top domain",
                    reviewed_at=now,
                )
            )
            changed += 1
            continue

        if existing.status != "approved":
            existing.status = "approved"
            existing.reviewed_by_admin_id = admin_user.id
            existing.review_note = "System-approved top domain"
            existing.reviewed_at = now
            changed += 1

    if changed:
        db.session.commit()
    print(f"Top verified domains bootstrap complete. Updated: {changed}, Target: {len(domains)}")


with app.app_context():
    db.create_all()
    admin_user = bootstrap_admin()
    bootstrap_extension_reporter()
    bootstrap_top_verified_domains(admin_user, limit=100)


@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/")
def home():
    return """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Community Phishing Reports</title>
    <style>
      :root {
        --bg: #f4f7ff;
        --card-bg: #ffffffcc;
        --text: #111827;
        --muted: #5b6474;
        --line: #d7deea;
        --primary: #2563eb;
        --primary-2: #1d4ed8;
        --secondary: #475467;
        --warn: #b54708;
        --ok: #067647;
        --danger: #b42318;
      }
      * { box-sizing: border-box; }
      html, body { min-height: 100%; }
      body {
        font-family: Inter, Segoe UI, Arial, sans-serif;
        max-width: 1120px;
        margin: 0 auto;
        padding: 22px 14px 28px;
        background:
          radial-gradient(1200px 600px at 10% -10%, #dbeafe 0%, transparent 50%),
          radial-gradient(900px 600px at 95% 0%, #e0e7ff 0%, transparent 45%),
          var(--bg);
        color: var(--text);
        line-height: 1.45;
      }
      h2 {
        margin: 0 0 6px;
        letter-spacing: 0.2px;
        font-size: 28px;
        background: linear-gradient(90deg, #0f172a, #1d4ed8 60%, #4338ca);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
      }
      h3, h4 { margin-top: 2px; letter-spacing: 0.2px; }
      p { margin: 0; }
      .card {
        background: var(--card-bg);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 16px;
        margin: 12px 0;
        box-shadow: 0 8px 24px rgba(17, 24, 39, 0.06);
        backdrop-filter: blur(4px);
        position: relative;
        overflow: hidden;
      }
      .card::before {
        content: "";
        position: absolute;
        inset: 0;
        pointer-events: none;
        background: linear-gradient(180deg, rgba(255,255,255,0.24), rgba(255,255,255,0));
      }
      .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
      input, select, textarea, button {
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid #c4cede;
        font-size: 14px;
      }
      input:focus, select:focus, textarea:focus {
        outline: none;
        border-color: #7aa2ff;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
      }
      textarea { width: 100%; min-height: 100px; resize: vertical; }
      input[type='text'], input[type='password'], input[type='email'], select { min-width: 220px; flex: 1; }
      input[type='file'] { background: #fff; }
      input::placeholder, textarea::placeholder { color: #8b95a7; }
      button {
        background: linear-gradient(180deg, var(--primary), var(--primary-2));
        color: #fff;
        border: none;
        cursor: pointer;
        font-weight: 600;
        transition: transform .12s ease, box-shadow .12s ease, opacity .12s ease;
      }
      button:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(37, 99, 235, 0.25); }
      button:active { transform: translateY(0); }
      button.secondary { background: linear-gradient(180deg, #667085, var(--secondary)); }
      button.warn { background: linear-gradient(180deg, #d05b1b, var(--warn)); }
      .muted { color: var(--muted); }
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 12px;
        border: 1px solid #d5def0;
        background: #eef3ff;
      }
      .tabs { display: flex; gap: 8px; flex-wrap: wrap; }
      .tabs button { margin-right: 0; border-radius: 999px; padding: 9px 14px; }
      .hidden { display: none; }
      .danger { color: var(--danger); font-weight: 600; }
      .ok { color: var(--ok); font-weight: 600; }
      img.thumb {
        max-width: 230px;
        border: 1px solid #d3dae3;
        border-radius: 10px;
        box-shadow: 0 6px 18px rgba(2, 6, 23, 0.12);
      }
      code {
        background: #eef2ff;
        border: 1px solid #dfe6ff;
        border-radius: 6px;
        padding: 1px 6px;
      }
      #stats .badge {
        background: linear-gradient(180deg, #f8fbff, #ecf2ff);
        border-color: #cddcff;
        font-weight: 600;
      }
      #liveFeed .card, #community .card, #bizRequests .card, #adminReports .card, #adminVerifications .card {
        border-radius: 12px;
        margin: 10px 0;
      }
      #community .card {
        border-left: 4px solid #7c93ff;
      }
      #adminReports .card {
        border-left: 4px solid #ffb86b;
      }
      #adminVerifications .card {
        border-left: 4px solid #93c5fd;
      }
      .muted + .row, .muted + div, .row + .muted { margin-top: 8px; }
      ::-webkit-scrollbar { height: 8px; width: 8px; }
      ::-webkit-scrollbar-track { background: #edf1f9; border-radius: 8px; }
      ::-webkit-scrollbar-thumb { background: #c3cce0; border-radius: 8px; }
      ::-webkit-scrollbar-thumb:hover { background: #a9b6d3; }
      @media (max-width: 740px) {
        body { padding: 14px 10px 22px; }
        .card { border-radius: 12px; padding: 14px; }
        h2 { font-size: 24px; }
      }
    </style>
  </head>
  <body>
    <h2>Community-Driven Phishing Reporting</h2>
    <p class="muted">No automated analysis here. Community reports, voting, statistics, and admin governance only.</p>

    <div id="authBox" class="card">
      <h3>Login / Register</h3>
      <div class="row">
        <input id="username" type="text" placeholder="Username" />
        <input id="email" type="email" placeholder="Email (for register)" />
        <input id="password" type="password" placeholder="Password" />
        <select id="role">
          <option value="user">User</option>
          <option value="business">Business</option>
          <option value="admin">Admin (login only)</option>
        </select>
      </div>
      <div class="row" style="margin-top:8px;">
        <button onclick="registerUser()">Register</button>
        <button class="secondary" onclick="loginUser()">Login</button>
      </div>
      <p class="muted">Default admin (first run): username <code>admin</code> password <code>admin123</code></p>
      <div id="authMsg"></div>
    </div>

    <div id="appBox" class="hidden">
      <div class="card">
        <div class="row">
          <div><strong id="who"></strong> <span id="roleBadge" class="badge"></span></div>
          <button class="secondary" onclick="logoutUser()">Logout</button>
        </div>
      </div>

      <div class="card tabs">
        <button onclick="setTab('dashboard')">Dashboard</button>
        <button onclick="setTab('report')">Report Website</button>
        <button onclick="setTab('community')">Community</button>
        <button id="businessTabBtn" class="hidden" onclick="setTab('business')">Business Verification</button>
        <button id="adminTabBtn" class="hidden warn" onclick="setTab('admin')">Admin</button>
      </div>

      <div id="tab-dashboard" class="card">
        <h3>Statistics</h3>
        <div id="stats"></div>
        <h4>Live feed</h4>
        <div id="liveFeed"></div>
      </div>

      <div id="tab-report" class="card hidden">
        <h3>Report Phishing Website</h3>
        <p class="muted">Screenshot and details are mandatory.</p>
        <div class="row">
          <input id="reportUrl" type="text" placeholder="Website URL (required)" />
          <input id="reportTitle" type="text" placeholder="Short title (required)" />
        </div>
        <div style="margin-top:8px;">
          <textarea id="reportDetails" placeholder="Explain why this looks like phishing (required)"></textarea>
        </div>
        <div style="margin-top:8px;" class="row">
          <input id="reportImage" type="file" accept="image/*" />
          <button onclick="submitReport()">Submit Report</button>
        </div>
        <div id="reportMsg"></div>
      </div>

      <div id="tab-community" class="card hidden">
        <h3>Community Judgements</h3>
        <div id="community"></div>
      </div>

      <div id="tab-business" class="card hidden">
        <h3>Business Verification Request</h3>
        <p class="muted">Approved businesses hide score/verdict to avoid public misclassification.</p>
        <div class="row">
          <input id="bizName" type="text" placeholder="Business name" />
          <input id="bizDomain" type="text" placeholder="Website domain or URL" />
        </div>
        <div style="margin-top:8px;">
          <textarea id="bizProof" placeholder="Proof details (ownership, registration, contacts)"></textarea>
        </div>
        <div class="row" style="margin-top:8px;">
          <button onclick="submitBusinessVerification()">Get Verified</button>
        </div>
        <div id="bizMsg"></div>
        <h4>Your requests</h4>
        <div id="bizRequests"></div>
      </div>

      <div id="tab-admin" class="card hidden">
        <h3>Admin Panel</h3>
        <h4>Manage reports</h4>
        <div id="adminReports"></div>
        <h4>Business verification requests</h4>
        <div id="adminVerifications"></div>
      </div>
    </div>

    <script>
      let currentTab = 'dashboard';
      let me = null;

      function esc(s) {
        return (s || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
      }

      function setTab(name) {
        currentTab = name;
        ['dashboard','report','community','business','admin'].forEach(t => {
          document.getElementById('tab-' + t).classList.toggle('hidden', t !== name);
        });
      }

      async function api(path, options = {}) {
        const resp = await fetch(path, {
          credentials: 'same-origin',
          ...options
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Request failed');
        return data;
      }

      function showMsg(id, text, cls = '') {
        const el = document.getElementById(id);
        el.className = cls;
        el.textContent = text;
      }

      async function registerUser() {
        try {
          const role = document.getElementById('role').value;
          if (role === 'admin') throw new Error('Admin registration is disabled');
          const payload = {
            username: document.getElementById('username').value.trim(),
            email: document.getElementById('email').value.trim(),
            password: document.getElementById('password').value,
            role: role
          };
          await api('/api/register', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
          showMsg('authMsg', 'Registered. You can now login.', 'ok');
        } catch (e) {
          showMsg('authMsg', String(e.message), 'danger');
        }
      }

      async function loginUser() {
        try {
          const payload = {
            username: document.getElementById('username').value.trim(),
            password: document.getElementById('password').value
          };
          await api('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
          await loadMe();
          showMsg('authMsg', 'Login successful', 'ok');
        } catch (e) {
          showMsg('authMsg', String(e.message), 'danger');
        }
      }

      async function logoutUser() {
        await api('/api/logout', { method: 'POST' });
        me = null;
        document.getElementById('authBox').classList.remove('hidden');
        document.getElementById('appBox').classList.add('hidden');
      }

      async function loadMe() {
        try {
          me = await api('/api/me');
          document.getElementById('authBox').classList.add('hidden');
          document.getElementById('appBox').classList.remove('hidden');
          document.getElementById('who').textContent = me.username;
          document.getElementById('roleBadge').textContent = me.role;
          document.getElementById('businessTabBtn').classList.toggle('hidden', me.role !== 'business');
          document.getElementById('adminTabBtn').classList.toggle('hidden', me.role !== 'admin');
          await refreshAll();
        } catch {
          document.getElementById('authBox').classList.remove('hidden');
          document.getElementById('appBox').classList.add('hidden');
        }
      }

      async function submitReport() {
        try {
          const file = document.getElementById('reportImage').files[0];
          const details = document.getElementById('reportDetails').value.trim();
          const title = document.getElementById('reportTitle').value.trim();
          const website_url = document.getElementById('reportUrl').value.trim();
          if (!file) throw new Error('Screenshot is mandatory');
          if (!details || !title || !website_url) throw new Error('URL, title, and details are required');
          const form = new FormData();
          form.append('website_url', website_url);
          form.append('title', title);
          form.append('details', details);
          form.append('screenshot', file);
          await api('/api/reports', { method: 'POST', body: form });
          showMsg('reportMsg', 'Report submitted successfully', 'ok');
          document.getElementById('reportDetails').value = '';
          document.getElementById('reportTitle').value = '';
          document.getElementById('reportUrl').value = '';
          document.getElementById('reportImage').value = '';
          await refreshAll();
        } catch (e) {
          showMsg('reportMsg', String(e.message), 'danger');
        }
      }

      async function vote(reportId, voteType) {
        try {
          await api('/api/reports/' + reportId + '/vote', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ vote: voteType })
          });
          await refreshAll();
        } catch (e) {
          alert(e.message);
        }
      }

      async function submitBusinessVerification() {
        try {
          const payload = {
            business_name: document.getElementById('bizName').value.trim(),
            website_domain: document.getElementById('bizDomain').value.trim(),
            proof_details: document.getElementById('bizProof').value.trim()
          };
          await api('/api/business/verification-request', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(payload)
          });
          showMsg('bizMsg', 'Verification request submitted', 'ok');
          await refreshBusinessRequests();
        } catch (e) {
          showMsg('bizMsg', String(e.message), 'danger');
        }
      }

      async function adminSetReport(reportId, status) {
        const note = prompt('Optional admin note:', '') || '';
        await api('/api/admin/reports/' + reportId, {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ status, admin_note: note })
        });
        await refreshAll();
      }

      async function adminSetVerification(id, status) {
        const note = prompt('Optional review note:', '') || '';
        await api('/api/admin/verification-requests/' + id, {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ status, review_note: note })
        });
        await refreshAll();
      }

      async function refreshDashboard() {
        const data = await api('/api/dashboard');
        document.getElementById('stats').innerHTML = `
          <div class="row">
            <div class="badge">Total reports: ${data.stats.total_reports}</div>
            <div class="badge">Open reports: ${data.stats.open_reports}</div>
            <div class="badge">Under review: ${data.stats.under_review_reports}</div>
            <div class="badge">Resolved: ${data.stats.resolved_reports}</div>
            <div class="badge">Verified businesses: ${data.stats.verified_businesses}</div>
          </div>
        `;
        document.getElementById('liveFeed').innerHTML = data.live_feed.map(item => `
          <div class="card">
            <strong>${esc(item.domain)}</strong> reported ${item.report_count} time(s) | Verdict: ${esc(item.verdict)}
            <div class="muted">Last update: ${esc(item.last_update)}</div>
          </div>
        `).join('') || '<div class="muted">No reports yet.</div>';
      }

      async function refreshCommunity() {
        const data = await api('/api/reports');
        document.getElementById('community').innerHTML = data.reports.map(r => `
          <div class="card">
            <div><strong>${esc(r.title)}</strong> <span class="badge">${esc(r.status)}</span></div>
            <div class="muted">${esc(r.website_url)} (${esc(r.domain)})</div>
            <div>By: ${esc(r.reporter)} (${esc(r.reporter_role)})</div>
            <p>${esc(r.details)}</p>
            <div>Votes: phishing=${r.phishing_votes}, non-phishing=${r.non_phishing_votes}</div>
            <div><strong>Community verdict:</strong> ${esc(r.community_verdict)}</div>
            <div><img class="thumb" src="${esc(r.screenshot_path)}" alt="screenshot" /></div>
            ${r.verified_business ? '<p class="ok">Verified business: verdict hidden from public scoring.</p>' : ''}
            <div class="row" style="margin-top:8px;">
              <button onclick="vote(${r.id}, 'phishing')">Vote Phishing</button>
              <button class="secondary" onclick="vote(${r.id}, 'non_phishing')">Vote Non-Phishing</button>
            </div>
          </div>
        `).join('') || '<div class="muted">No community reports yet.</div>';
      }

      async function refreshBusinessRequests() {
        if (!me || me.role !== 'business') return;
        const data = await api('/api/business/verification-requests');
        document.getElementById('bizRequests').innerHTML = data.requests.map(r => `
          <div class="card">
            <strong>${esc(r.business_name)}</strong> for ${esc(r.website_domain)}
            <div>Status: <span class="badge">${esc(r.status)}</span></div>
            <div class="muted">Note: ${esc(r.review_note || 'None')}</div>
          </div>
        `).join('') || '<div class="muted">No requests submitted yet.</div>';
      }

      async function refreshAdmin() {
        if (!me || me.role !== 'admin') return;
        const data = await api('/api/admin/overview');
        document.getElementById('adminReports').innerHTML = data.reports.map(r => `
          <div class="card">
            <strong>${esc(r.title)}</strong> - ${esc(r.domain)} <span class="badge">${esc(r.status)}</span>
            <div class="muted">${esc(r.website_url)}</div>
            <div>${esc(r.details)}</div>
            <div class="row" style="margin-top:8px;">
              <button onclick="adminSetReport(${r.id}, 'under_review')">Set Under Review</button>
              <button class="secondary" onclick="adminSetReport(${r.id}, 'resolved')">Resolve</button>
              <button class="warn" onclick="adminSetReport(${r.id}, 'open')">Reopen</button>
            </div>
          </div>
        `).join('') || '<div class="muted">No reports found.</div>';

        document.getElementById('adminVerifications').innerHTML = data.verification_requests.map(v => `
          <div class="card">
            <strong>${esc(v.business_name)}</strong> (${esc(v.website_domain)}) - <span class="badge">${esc(v.status)}</span>
            <div>${esc(v.proof_details)}</div>
            <div class="row" style="margin-top:8px;">
              <button onclick="adminSetVerification(${v.id}, 'approved')">Approve</button>
              <button class="warn" onclick="adminSetVerification(${v.id}, 'rejected')">Reject</button>
            </div>
          </div>
        `).join('') || '<div class="muted">No verification requests.</div>';
      }

      async function refreshAll() {
        if (!me) return;
        await Promise.all([refreshDashboard(), refreshCommunity(), refreshBusinessRequests(), refreshAdmin()]);
      }

      setInterval(() => { refreshAll().catch(() => {}); }, 5000);
      loadMe();
    </script>
  </body>
</html>
"""


@app.route("/api/public/domain-status")
def public_domain_status():
    raw_url = request.args.get("url", "")
    url = normalize_url(raw_url)
    domain = normalize_domain(url)
    if not domain:
        return jsonify({"error": "Invalid or missing url"}), 400

    reports = Report.query.filter_by(domain=domain).order_by(Report.created_at.desc()).all()
    report_count = len(reports)
    phishing_votes = 0
    non_phishing_votes = 0
    for report in reports:
        p_votes, n_votes = compute_report_counts(report)
        phishing_votes += p_votes
        non_phishing_votes += n_votes

    verified = is_verified_business_domain(domain)
    if verified:
        verdict = "Hidden for verified business"
        status = "Verified"
    elif phishing_votes > non_phishing_votes and phishing_votes > 0:
        verdict = "Likely phishing"
        status = "Phishing"
    elif non_phishing_votes > phishing_votes and non_phishing_votes > 0:
        verdict = "Likely non-phishing"
        status = "Safe"
    else:
        verdict = "Undecided"
        status = "Suspicious" if report_count > 0 else "Unknown"

    return jsonify(
        {
            "url": url,
            "domain": domain,
            "verified_business": verified,
            "report_count": report_count,
            "phishing_votes": phishing_votes,
            "non_phishing_votes": non_phishing_votes,
            "community_verdict": verdict,
            "status": status,
        }
    )


@app.route("/api/public/no-screenshot")
def no_screenshot():
    svg = """<svg xmlns='http://www.w3.org/2000/svg' width='640' height='360'>
<rect width='100%' height='100%' fill='#f3f4f6'/>
<text x='50%' y='45%' dominant-baseline='middle' text-anchor='middle' fill='#6b7280' font-size='24' font-family='Arial'>No Screenshot</text>
<text x='50%' y='58%' dominant-baseline='middle' text-anchor='middle' fill='#9ca3af' font-size='16' font-family='Arial'>Submitted from browser extension quick report</text>
</svg>"""
    return Response(svg, mimetype="image/svg+xml")


@app.route("/api/extension/report", methods=["POST"])
def extension_report():
    data = request.get_json(silent=True) or {}
    website_url = normalize_url(data.get("url") or data.get("website_url"))
    title = (data.get("title") or "Extension quick report").strip()
    details = (data.get("details") or "Reported from browser extension").strip()
    if not website_url:
        return jsonify({"error": "url is required"}), 400

    domain = normalize_domain(website_url)
    if not domain:
        return jsonify({"error": "Invalid url"}), 400
    if is_verified_business_domain(domain):
        return jsonify({"error": "Quick report is disabled for verified businesses"}), 403

    reporter = User.query.filter_by(username="extension_reporter").first()
    if not reporter:
        reporter = bootstrap_extension_reporter()

    report = Report(
        reporter_id=reporter.id,
        website_url=website_url,
        domain=domain,
        title=title,
        details=details,
        screenshot_path="/api/public/no-screenshot",
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({"message": "Report submitted", "report": report_to_public_dict(report)})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = (data.get("role") or "user").strip().lower()

    if role not in {"user", "business"}:
        return jsonify({"error": "Invalid role for registration"}), 400
    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already exists"}), 409

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=role,
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Registered successfully"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user.id
    return jsonify({"message": "Login successful", "role": user.role})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return jsonify({"message": "Logged out"})


@app.route("/api/me")
@login_required
def me(user):
    return jsonify({"id": user.id, "username": user.username, "email": user.email, "role": user.role})


@app.route("/api/reports", methods=["GET"])
@login_required
def list_reports(user):
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return jsonify({"reports": [report_to_public_dict(r) for r in reports]})


@app.route("/api/reports", methods=["POST"])
@login_required
@role_required("user", "business", "admin")
def create_report(user):
    website_url = normalize_url(request.form.get("website_url"))
    title = (request.form.get("title") or "").strip()
    details = (request.form.get("details") or "").strip()
    screenshot = request.files.get("screenshot")

    if not website_url or not title or not details:
        return jsonify({"error": "website_url, title, and details are required"}), 400
    if not screenshot:
        return jsonify({"error": "Screenshot upload is mandatory"}), 400

    domain = normalize_domain(website_url)
    if not domain:
        return jsonify({"error": "Invalid website URL"}), 400

    filename = secure_filename(screenshot.filename or "")
    if not filename:
        return jsonify({"error": "Invalid screenshot file name"}), 400
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        return jsonify({"error": "Unsupported image format"}), 400
    stored_name = f"{uuid.uuid4().hex}{ext}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)
    screenshot.save(save_path)

    report = Report(
        reporter_id=user.id,
        website_url=website_url,
        domain=domain,
        title=title,
        details=details,
        screenshot_path=f"/uploads/{stored_name}",
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({"message": "Report submitted", "report": report_to_public_dict(report)})


@app.route("/api/reports/<int:report_id>/vote", methods=["POST"])
@login_required
@role_required("user", "business", "admin")
def vote_report(user, report_id):
    data = request.get_json(silent=True) or {}
    vote_value = (data.get("vote") or "").strip().lower()
    if vote_value not in {"phishing", "non_phishing"}:
        return jsonify({"error": "vote must be phishing or non_phishing"}), 400

    report = db.session.get(Report, report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404

    existing = ReportVote.query.filter_by(report_id=report_id, user_id=user.id).first()
    if existing:
        existing.vote = vote_value
        existing.created_at = datetime.utcnow()
    else:
        db.session.add(ReportVote(report_id=report_id, user_id=user.id, vote=vote_value))
    db.session.commit()
    return jsonify({"message": "Vote recorded", "report": report_to_public_dict(report)})


@app.route("/api/dashboard")
@login_required
def dashboard(user):
    total_reports = Report.query.count()
    open_reports = Report.query.filter_by(status="open").count()
    under_review_reports = Report.query.filter_by(status="under_review").count()
    resolved_reports = Report.query.filter_by(status="resolved").count()
    verified_businesses = BusinessVerificationRequest.query.filter_by(status="approved").count()

    grouped = {}
    reports = Report.query.order_by(Report.created_at.desc()).all()
    for report in reports:
        entry = grouped.get(report.domain)
        if not entry:
            entry = {
                "domain": report.domain,
                "report_count": 0,
                "last_update": report.created_at.isoformat(),
                "phishing_votes": 0,
                "non_phishing_votes": 0,
                "verified": is_verified_business_domain(report.domain),
            }
            grouped[report.domain] = entry
        entry["report_count"] += 1
        p_votes, n_votes = compute_report_counts(report)
        entry["phishing_votes"] += p_votes
        entry["non_phishing_votes"] += n_votes
        if report.created_at.isoformat() > entry["last_update"]:
            entry["last_update"] = report.created_at.isoformat()

    live_feed = []
    for item in grouped.values():
        if item["verified"]:
            verdict = "Hidden for verified business"
        elif item["phishing_votes"] > item["non_phishing_votes"]:
            verdict = "Likely phishing"
        elif item["non_phishing_votes"] > item["phishing_votes"]:
            verdict = "Likely non-phishing"
        else:
            verdict = "Undecided"
        live_feed.append(
            {
                "domain": item["domain"],
                "report_count": item["report_count"],
                "last_update": item["last_update"],
                "verdict": verdict,
            }
        )

    live_feed.sort(key=lambda x: x["report_count"], reverse=True)
    return jsonify(
        {
            "stats": {
                "total_reports": total_reports,
                "open_reports": open_reports,
                "under_review_reports": under_review_reports,
                "resolved_reports": resolved_reports,
                "verified_businesses": verified_businesses,
            },
            "live_feed": live_feed[:50],
        }
    )


@app.route("/api/business/verification-request", methods=["POST"])
@login_required
@role_required("business")
def create_verification_request(user):
    data = request.get_json(silent=True) or {}
    business_name = (data.get("business_name") or "").strip()
    website_domain = normalize_domain(data.get("website_domain"))
    proof_details = (data.get("proof_details") or "").strip()
    if not business_name or not website_domain or not proof_details:
        return jsonify({"error": "business_name, website_domain and proof_details are required"}), 400

    existing = BusinessVerificationRequest.query.filter_by(website_domain=website_domain).first()
    if existing:
        return jsonify({"error": "Request already exists for this domain"}), 409

    req_item = BusinessVerificationRequest(
        business_user_id=user.id,
        website_domain=website_domain,
        business_name=business_name,
        proof_details=proof_details,
        status="pending",
    )
    db.session.add(req_item)
    db.session.commit()
    return jsonify({"message": "Verification request submitted", "request": req_item.to_dict()})


@app.route("/api/business/verification-requests")
@login_required
@role_required("business")
def list_my_verification_requests(user):
    items = BusinessVerificationRequest.query.filter_by(business_user_id=user.id).order_by(BusinessVerificationRequest.created_at.desc()).all()
    return jsonify({"requests": [item.to_dict() for item in items]})


@app.route("/api/admin/overview")
@login_required
@role_required("admin")
def admin_overview(user):
    reports = Report.query.order_by(Report.created_at.desc()).all()
    verifications = BusinessVerificationRequest.query.order_by(BusinessVerificationRequest.created_at.desc()).all()
    return jsonify(
        {
            "reports": [report_to_public_dict(r) for r in reports],
            "verification_requests": [v.to_dict() for v in verifications],
        }
    )


@app.route("/api/admin/reports/<int:report_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_update_report(user, report_id):
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()
    admin_note = (data.get("admin_note") or "").strip()
    if status not in {"open", "under_review", "resolved"}:
        return jsonify({"error": "Invalid status"}), 400
    report = db.session.get(Report, report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    report.status = status
    report.admin_note = admin_note or None
    db.session.commit()
    return jsonify({"message": "Report updated", "report": report_to_public_dict(report)})


@app.route("/api/admin/verification-requests/<int:req_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_update_verification(user, req_id):
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()
    review_note = (data.get("review_note") or "").strip()
    if status not in {"approved", "rejected"}:
        return jsonify({"error": "Status must be approved or rejected"}), 400
    req_item = db.session.get(BusinessVerificationRequest, req_id)
    if not req_item:
        return jsonify({"error": "Verification request not found"}), 404
    req_item.status = status
    req_item.review_note = review_note or None
    req_item.reviewed_by_admin_id = user.id
    req_item.reviewed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Verification request updated", "request": req_item.to_dict()})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)