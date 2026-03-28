const API = "http://localhost:5000";

// ===== NAVIGATION =====
const navItems = document.querySelectorAll(".nav-item");
const sections = document.querySelectorAll(".section");
const pageTitle = document.getElementById("page-title");
const pageSub = document.getElementById("page-sub");

const pageMeta = {
  dashboard: {
    title: "Overview Dashboard",
    sub: "Real-time threat monitoring & email compromise detection",
  },
  emails: {
    title: "Email Analysis",
    sub: "Incoming email risk scoring and classification",
  },
  sandbox: {
    title: "Link Sandbox",
    sub: "Isolated URL analysis and malicious link detection",
  },
  login: {
    title: "Login Behavior",
    sub: "User anomaly detection via location, time & device monitoring",
  },
  alerts: {
    title: "Alerts & Notifications",
    sub: "Active threat alerts sent to receiver and administrator",
  },
};

navItems.forEach((item) => {
  item.addEventListener("click", (e) => {
    e.preventDefault();
    const target = item.dataset.section;
    navItems.forEach((n) => n.classList.remove("active"));
    item.classList.add("active");
    sections.forEach((s) => s.classList.remove("active"));
    document.getElementById(`section-${target}`).classList.add("active");
    pageTitle.textContent = pageMeta[target].title;
    pageSub.textContent = pageMeta[target].sub;
  });
});

// ===== LIVE CLOCK =====
function updateClock() {
  const el = document.getElementById("live-time");
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString("en-IN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
updateClock();
setInterval(updateClock, 1000);

// ===== COUNTER ANIMATION =====
function animateCounters() {
  document.querySelectorAll(".counter").forEach((el) => {
    const target = parseInt(el.dataset.target);
    let current = 0;
    const step = Math.ceil(target / 40);
    const timer = setInterval(() => {
      current += step;
      if (current >= target) {
        current = target;
        clearInterval(timer);
      }
      el.textContent = current;
    }, 30);
  });
}
animateCounters();

// ===== EMAIL FILTER =====
document.querySelectorAll(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document
      .querySelectorAll(".filter-btn")
      .forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const filter = btn.dataset.filter;
    document.querySelectorAll("#email-tbody tr").forEach((row) => {
      row.style.display =
        filter === "all" || row.dataset.risk === filter ? "" : "none";
    });
  });
});

// ===== EMAIL SEARCH =====
document.getElementById("email-search").addEventListener("input", function () {
  const val = this.value.toLowerCase();
  document.querySelectorAll("#email-tbody tr").forEach((row) => {
    row.style.display = row.textContent.toLowerCase().includes(val)
      ? ""
      : "none";
  });
});

// ===== EMAIL MODAL =====
function openEmailModal(sender, subject, body, hasLink, score, risk) {
  const modal = document.getElementById("modal-overlay");
  const mb = document.getElementById("modal-body");
  const riskColor =
    risk === "High"
      ? "var(--danger)"
      : risk === "Medium"
        ? "var(--warning)"
        : "var(--success)";
  const action =
    risk === "High"
      ? '<span style="color:var(--danger);font-weight:600;"><i class="fa-solid fa-lock"></i> Quarantined — Admin & Receiver Notified</span>'
      : risk === "Medium"
        ? '<span style="color:var(--warning);font-weight:600;"><i class="fa-solid fa-triangle-exclamation"></i> Warning Sent — Proceed with Caution</span>'
        : '<span style="color:var(--success);font-weight:600;"><i class="fa-solid fa-check-circle"></i> Delivered to Inbox</span>';

  mb.innerHTML = `
    <div class="modal-row"><span class="modal-label">From</span><span class="modal-val"><code style="font-family:'DM Mono',monospace;color:var(--info)">${sender}</code></span></div>
    <div class="modal-row"><span class="modal-label">Subject</span><span class="modal-val">${subject}</span></div>
    <div class="modal-row"><span class="modal-label">Has Link</span><span class="modal-val">${hasLink}</span></div>
    <div class="modal-row"><span class="modal-label">Risk Score</span>
      <span class="modal-val" style="color:${riskColor};font-family:'DM Mono',monospace;font-weight:600;">${score}/100</span>
    </div>
    <div class="modal-row"><span class="modal-label">Classification</span>
      <span class="modal-val"><span class="badge ${risk.toLowerCase()}">${risk} Risk</span></span>
    </div>
    <div class="modal-body-text">${body}</div>
    <div class="modal-row"><span class="modal-label">System Action</span><span class="modal-val">${action}</span></div>
    <div style="margin-top:16px;padding:12px;background:var(--bg3);border-radius:8px;font-size:12px;color:var(--text3);font-family:'DM Mono',monospace;">
      <i class="fa-solid fa-shield-halved" style="color:var(--info)"></i>&nbsp;
      Analyzed by BEC Shield Risk Engine — ${new Date().toLocaleString()}
    </div>
  `;
  modal.classList.add("open");
}

function closeModal() {
  document.getElementById("modal-overlay").classList.remove("open");
}

// ===== HELPER: ADD TO LIVE FEED =====
function addToFeed(type, icon, title, msg, badge) {
  const feed = document.getElementById("live-feed");
  if (!feed) return;
  const item = document.createElement("div");
  item.className = `lf-item ${type}`;
  item.style.opacity = "0";
  item.style.transform = "translateY(-10px)";
  item.innerHTML = `
    <div class="lf-icon"><i class="fa-solid ${icon}"></i></div>
    <div class="lf-content">
      <strong>${title}</strong> — ${msg}
      <span class="lf-time">Just now</span>
    </div>
    <span class="lf-badge ${type}">${badge}</span>
  `;
  feed.insertBefore(item, feed.firstChild);
  setTimeout(() => {
    item.style.transition = "all 0.4s ease";
    item.style.opacity = "1";
    item.style.transform = "translateY(0)";
  }, 50);
  const items = feed.querySelectorAll(".lf-item");
  if (items.length > 6) {
    const last = items[items.length - 1];
    last.style.transition = "opacity 0.3s";
    last.style.opacity = "0";
    setTimeout(() => last.remove(), 300);
  }
}

// ===== HELPER: ADD ALERT CARD =====
function addAlertCard(type, icon, title, desc, meta) {
  const list = document.getElementById("alerts-list");
  if (!list) return;
  const card = document.createElement("div");
  card.className = `alert-card ${type}`;
  card.innerHTML = `
    <div class="alert-icon"><i class="fa-solid ${icon}"></i></div>
    <div class="alert-body">
      <div class="alert-title">${title}</div>
      <div class="alert-desc">${desc}</div>
      <div class="alert-meta"><i class="fa-solid fa-clock"></i> Just now &nbsp;|&nbsp; ${meta}</div>
    </div>
    <button class="dismiss-btn" onclick="dismissAlert(this)"><i class="fa-solid fa-xmark"></i></button>
  `;
  list.prepend(card);
}

// ===== SANDBOX — REAL BACKEND =====
async function runSandbox() {
  const url = document.getElementById("sandbox-url").value.trim();
  const resultEl = document.getElementById("sandbox-result");

  if (!url) {
    resultEl.style.display = "block";
    resultEl.style.background = "var(--warning-dim)";
    resultEl.style.border = "1px solid rgba(255,170,0,0.3)";
    resultEl.style.color = "var(--warning)";
    resultEl.innerHTML =
      '<i class="fa-solid fa-triangle-exclamation"></i> Please enter a URL to analyze.';
    return;
  }

  resultEl.style.display = "block";
  resultEl.style.background = "var(--info-dim)";
  resultEl.style.border = "1px solid rgba(77,159,255,0.3)";
  resultEl.style.color = "var(--info)";
  resultEl.innerHTML =
    '<i class="fa-solid fa-spinner fa-spin"></i> Running sandbox analysis...';

  try {
    const res = await fetch(`${API}/api/sandbox`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    const vMap = {
      malicious: {
        color: "var(--danger)",
        bg: "var(--danger-dim)",
        border: "rgba(255,59,92,0.3)",
        icon: "fa-skull-crossbones",
      },
      suspicious: {
        color: "var(--warning)",
        bg: "var(--warning-dim)",
        border: "rgba(255,170,0,0.3)",
        icon: "fa-triangle-exclamation",
      },
      safe: {
        color: "var(--success)",
        bg: "var(--success-dim)",
        border: "rgba(0,214,143,0.3)",
        icon: "fa-circle-check",
      },
    };
    const v = vMap[data.verdict] || vMap["safe"];

    resultEl.style.background = v.bg;
    resultEl.style.border = `1px solid ${v.border}`;
    resultEl.style.color = v.color;
    resultEl.innerHTML = `
      <div style="font-weight:600;font-size:14px;margin-bottom:10px;">
        <i class="fa-solid ${v.icon}"></i> Verdict: ${data.verdict.toUpperCase()} &nbsp;|&nbsp; Threat Score: <strong>${data.threat_score}</strong>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px;">
        <div style="display:flex;justify-content:space-between;color:var(--text2);">
          <span>Domain Age</span><span style="color:${v.color}">
  ${
    data.details.domain_age_days === "Unknown" ||
    data.details.domain_age_days === -1
      ? "Unknown (WHOIS unavailable)"
      : data.details.domain_age_days + " days"
  }
</span>
        </div>
        <div style="display:flex;justify-content:space-between;color:var(--text2);">
          <span>Redirects</span><span style="color:${v.color}">${data.details.redirect_count}</span>
        </div>
        <div style="display:flex;justify-content:space-between;color:var(--text2);">
          <span>HTTPS</span>
          <span style="color:${data.details.https ? "var(--success)" : "var(--danger)"}">${data.details.https ? "Yes" : "No"}</span>
        </div>
        <div style="display:flex;justify-content:space-between;color:var(--text2);">
          <span>Known Malicious</span>
          <span style="color:${data.details.known_malicious ? "var(--danger)" : "var(--success)"}">${data.details.known_malicious ? "Yes" : "No"}</span>
        </div>
        ${
          data.details.suspicious_keywords &&
          data.details.suspicious_keywords.length > 0
            ? `
        <div style="display:flex;justify-content:space-between;color:var(--text2);">
          <span>Suspicious Keywords</span><span style="color:var(--warning)">${data.details.suspicious_keywords.join(", ")}</span>
        </div>`
            : ""
        }
      </div>
      ${
        data.reasons.length > 0
          ? `
      <div style="margin-top:10px;padding:8px;background:rgba(0,0,0,0.2);border-radius:6px;font-size:11px;color:var(--text3);">
        <strong style="color:${v.color}">Reasons:</strong> ${data.reasons.join(" • ")}
      </div>`
          : ""
      }
    `;

    // Add to live feed
    if (data.verdict !== "safe") {
      addToFeed(
        "high",
        "fa-bug",
        "SANDBOX ALERT",
        `Malicious link detected: <code>${url.slice(0, 40)}</code>`,
        "Flagged",
      );
    }
  } catch (err) {
    resultEl.style.background = "var(--danger-dim)";
    resultEl.style.border = "1px solid rgba(255,59,92,0.3)";
    resultEl.style.color = "var(--danger)";
    resultEl.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> Cannot connect to Flask backend. Run: <strong>python app.py</strong>`;
  }
}

// ===== FULL RISK ENGINE — REAL BACKEND =====
async function analyzeEmailFull(emailData, loginData = null) {
  try {
    const payload = { ...emailData };
    if (loginData) payload.login_data = loginData;

    const res = await fetch(`${API}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    const vMap = {
      high: {
        color: "var(--danger)",
        icon: "fa-skull-crossbones",
        badge: "high",
        feedType: "high",
      },
      medium: {
        color: "var(--warning)",
        icon: "fa-triangle-exclamation",
        badge: "medium",
        feedType: "medium",
      },
      safe: {
        color: "var(--success)",
        icon: "fa-circle-check",
        badge: "safe",
        feedType: "safe",
      },
    };
    const v = vMap[data.verdict] || vMap["safe"];

    // --- Update email table ---
    const tbody = document.getElementById("email-tbody");
    const newRow = document.createElement("tr");
    newRow.dataset.risk = data.verdict;
    newRow.style.opacity = "0";
    newRow.innerHTML = `
      <td><code>${emailData.sender}</code></td>
      <td>${emailData.subject}</td>
      <td><span class="tag ${emailData.has_link ? "yes" : "no"}">${emailData.has_link ? "Yes" : "No"}</span></td>
      <td>
        <div class="score-bar">
          <div class="score-fill ${data.verdict}" style="width:${data.final_score}%"></div>
          <span>${data.final_score}</span>
        </div>
      </td>
      <td><span class="badge ${data.verdict}">${data.verdict.charAt(0).toUpperCase() + data.verdict.slice(1)} Risk</span></td>
      <td>
        <button class="action-btn view"
          onclick="openEmailModal(
            '${emailData.sender.replace(/'/g, "\\'")}',
            '${emailData.subject.replace(/'/g, "\\'")}',
            '${(data.reasons || []).join(", ").replace(/'/g, "\\'").replace(/"/g, '\\"')}',
            '${emailData.has_link ? "Yes" : "No"}',
            '${data.final_score}',
            '${data.verdict ? data.verdict.charAt(0).toUpperCase() + data.verdict.slice(1) : "Unknown"}'
          )">View</button>
      </td>
    `;
    tbody.prepend(newRow);
    setTimeout(() => {
      newRow.style.transition = "opacity 0.4s";
      newRow.style.opacity = "1";
    }, 50);

    // --- Live feed ---
    const feedMsg = `Email from <code>${emailData.sender}</code>`;
    const feedBadge =
      data.verdict === "high"
        ? "Quarantined"
        : data.verdict === "medium"
          ? "Warning Sent"
          : "Delivered";
    addToFeed(
      v.feedType,
      v.icon,
      `${data.verdict.toUpperCase()} RISK`,
      feedMsg,
      feedBadge,
    );

    // --- Alert card (only for high/medium) ---
    if (data.verdict === "high") {
      addAlertCard(
        "high",
        "fa-skull-crossbones",
        "Email Quarantined — HIGH RISK",
        `Email from <code>${emailData.sender}</code> scored ${data.final_score}. Quarantined. Admin notified.`,
        `<i class="fa-solid fa-envelope"></i> ${emailData.sender}`,
      );
    } else if (data.verdict === "medium") {
      addAlertCard(
        "warning",
        "fa-triangle-exclamation",
        "Medium Risk Email — Warning Sent",
        `Email from <code>${emailData.sender}</code> scored ${data.final_score}. User warned.`,
        `<i class="fa-solid fa-envelope"></i> ${emailData.sender}`,
      );
    }

    return data;
  } catch (err) {
    console.error("Risk engine API error:", err);
    return null;
  }
}

// ===== LOGIN BEHAVIOR — REAL BACKEND =====
async function analyzeLogin(logEntry, previousEntry = null) {
  try {
    const res = await fetch(`${API}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        log_entry: logEntry,
        previous_entry: previousEntry,
      }),
    });
    const data = await res.json();

    // --- Add to anomaly list ---
    if (data.verdict !== "normal") {
      const anomalyList = document.querySelector(".anomaly-list");
      if (anomalyList) {
        const item = document.createElement("div");
        item.className = `anomaly-item ${data.verdict === "anomaly" ? "high" : "warning"}`;
        item.style.opacity = "0";
        item.innerHTML = `
          <div class="anomaly-icon"><i class="fa-solid fa-location-dot"></i></div>
          <div class="anomaly-info">
            <strong>${data.user}</strong>
            <span>${data.location} — Score: ${data.risk_score}</span>
            <div class="anomaly-meta">
              <span><i class="fa-solid fa-clock"></i> ${data.login_time}</span>
              <span><i class="fa-solid fa-desktop"></i> ${data.device}</span>
            </div>
          </div>
          <span class="badge ${data.verdict === "anomaly" ? "high" : "warning"}">
            ${data.verdict === "anomaly" ? "Blocked" : "Flagged"}
          </span>
        `;
        anomalyList.prepend(item);
        setTimeout(() => {
          item.style.transition = "opacity 0.4s";
          item.style.opacity = "1";
        }, 50);
      }

      // --- Feed ---
      addToFeed(
        "warning",
        "fa-user-slash",
        "LOGIN ANOMALY",
        `<code>${data.user}</code> logged in from ${data.location}`,
        "Alert Sent",
      );

      // --- Alert ---
      addAlertCard(
        "high",
        "fa-user-slash",
        "Login Anomaly Detected",
        `<code>${data.user}</code> login from ${data.location}. Risk Score: ${data.risk_score}. ${data.action}`,
        `<i class="fa-solid fa-location-dot"></i> ${data.location}`,
      );
    }

    return data;
  } catch (err) {
    console.error("Login API error:", err);
    return null;
  }
}

// ===== ALERT DISMISS =====
function dismissAlert(btn) {
  const card = btn.closest(".alert-card");
  card.style.transition = "all 0.3s ease";
  card.style.opacity = "0";
  card.style.transform = "translateX(20px)";
  setTimeout(() => card.remove(), 300);
}

function clearAlerts() {
  document.querySelectorAll(".alert-card").forEach((card) => {
    card.style.transition = "all 0.3s ease";
    card.style.opacity = "0";
    card.style.transform = "translateX(20px)";
    setTimeout(() => card.remove(), 300);
  });
}

// ===== AUTO DEMO ON PAGE LOAD =====
// Runs real API calls with sample data after page loads
window.addEventListener("load", () => {
  // Demo email 1 — High Risk (after 3s)
  setTimeout(() => {
    analyzeEmailFull(
      {
        sender: "ceo@fakebank.net",
        subject: "Urgent Wire Transfer Required",
        body: "Please transfer funds immediately. Verify your account or it will be suspended.",
        has_link: true,
        link_url: "http://malicious-site.com/verify",
      },
      {
        log_entry: {
          user_email: "john@company.com",
          login_time: new Date().toISOString().slice(0, 19).replace("T", " "),
          location: "Russia",
          device: "Unknown-Device",
          ip_address: "185.220.101.5",
        },
        previous_entry: {
          user_email: "john@company.com",
          login_time: "2024-01-15 09:00:00",
          location: "Mumbai",
          device: "Windows-PC",
          ip_address: "192.168.1.1",
        },
      },
    );
  }, 3000);

  // Demo email 2 — Safe (after 7s)
  setTimeout(() => {
    analyzeEmailFull({
      sender: "hr@company.com",
      subject: "Monthly Newsletter",
      body: "Here are the latest updates from our HR team this month.",
      has_link: true,
      link_url: "http://company.com/newsletter",
    });
  }, 7000);

  // Demo email 3 — Medium Risk (after 11s)
  setTimeout(() => {
    analyzeEmailFull({
      sender: "deals@promosite.com",
      subject: "Exclusive Weekend Offer",
      body: "Limited time offer. Click now to claim your prize. Act fast.",
      has_link: true,
      link_url: "http://suspicious-link.net/sale",
    });
  }, 11000);

  // Demo login anomaly (after 15s)
  setTimeout(() => {
    analyzeLogin(
      {
        user_email: "raj@company.com",
        login_time: new Date().toISOString().slice(0, 19).replace("T", " "),
        location: "Germany",
        device: "Unknown-Device",
        ip_address: "185.220.101.9",
      },
      {
        user_email: "raj@company.com",
        login_time: "2024-01-15 08:30:00",
        location: "Mumbai",
        device: "Windows-PC",
        ip_address: "192.168.1.10",
      },
    );
  }, 15000);
});
