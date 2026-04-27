let emailStatusTimer = null;
let emailEventsTimer = null;
let emailActionInFlight = false;
let emailPageState = null;
let emailScannerEnabled = true;
let lastEmailEventsFingerprint = "";
let selectedEmailEvent = null;

let manualConfigDirty = false;
let manualConfigFocusCount = 0;
let manualConfigHydrated = false;
const manualInputIds = ["emailManualHost", "emailManualPort", "emailManualSmtpHost", "emailManualSmtpPort"];

document.addEventListener("DOMContentLoaded", () => {
    emailPageState = document.getElementById("emailPageState");
    if (!emailPageState) return;

    initializeModuleInfoDialog();
    initializeMailboxConfigDialog();
    initializeManualConfigInputTracking();
    initializeEmailEventDetails();

    const toggleButton = document.getElementById("toggleEmailScanBtn");
    const runOnceButton = document.getElementById("runEmailScanOnceBtn");
    const applyManualButton = document.getElementById("applyEmailManualConfigBtn");

    if (toggleButton) {
        toggleButton.addEventListener("click", toggleEmailScanning);
    }
    if (runOnceButton) {
        runOnceButton.addEventListener("click", runEmailScanOnce);
    }
    if (applyManualButton) {
        applyManualButton.addEventListener("click", applyManualConnectionSettings);
    }

    refreshEmailStatus();
    refreshEmailEvents();

    emailStatusTimer = setInterval(refreshEmailStatus, 4000);
    emailEventsTimer = setInterval(refreshEmailEvents, 5000);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) return;
        refreshEmailStatus();
        refreshEmailEvents();
    });
});

async function refreshEmailStatus() {
    if (!emailPageState) return;

    try {
        const response = await fetch(emailPageState.dataset.statusUrl, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok || !data.success) {
            applyEmailAgentError(data.error || "Failed to load email analysis status.");
            return;
        }

        applyEmailAgentError("");
        applyEmailStatus(data);
    } catch (error) {
        applyEmailAgentError(`Failed to load status: ${error.message}`);
    }
}

function applyEmailStatus(data) {
    emailScannerEnabled = !!data.enabled;
    setEmailToggleState(emailScannerEnabled);

    const stats = data.stats || {};
    setNodeText("emailStatAnalysed", stats.emails_analysed ?? 0);
    setNodeText("emailStatSuspicious", stats.suspicious_emails ?? 0);
    setNodeText("emailStatPhishing", stats.phishing_emails ?? 0);
    setNodeText("emailStatLowRisk", stats.low_risk_emails ?? 0);
    setNodeText("emailStatLinks", stats.links_detected ?? 0);
    setNodeText("emailLastScanAt", formatTimestamp(data.last_scan_at));
    applyConnectionFields(data.connections || {}, { force: !manualConfigHydrated });

    if (data.last_error) {
        applyEmailAgentError(data.last_error);
    } else {
        applyEmailAgentError("");
    }
}

function setEmailToggleState(enabled) {
    const badge = document.getElementById("emailScanStatusBadge");
    const toggleButton = document.getElementById("toggleEmailScanBtn");

    if (badge) {
        badge.textContent = enabled ? "Running" : "Stopped";
        badge.classList.remove("badge-open", "badge-resolved");
        badge.classList.add(enabled ? "badge-open" : "badge-resolved");
    }

    if (toggleButton) {
        toggleButton.classList.remove("btn-danger", "btn-success");
        toggleButton.classList.add(enabled ? "btn-danger" : "btn-success");
        toggleButton.textContent = enabled ? "Turn Off Analysis" : "Turn On Analysis";
        toggleButton.disabled = emailActionInFlight;
    }
}

async function toggleEmailScanning() {
    if (!emailPageState || emailActionInFlight) return;

    const url = emailScannerEnabled ? emailPageState.dataset.stopUrl : emailPageState.dataset.startUrl;
    await runEmailControlAction(url, emailScannerEnabled ? "Email analysis disabled." : "Email analysis enabled.");
}

async function runEmailScanOnce() {
    if (!emailPageState || emailActionInFlight) return;
    await runEmailControlAction(emailPageState.dataset.runOnceUrl, "Email analysis cycle completed.");
}

async function runEmailControlAction(url, successMessage) {
    emailActionInFlight = true;
    updateEmailActionButtons();

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
            cache: "no-store",
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            applyEmailAgentError(data.error || "Email action failed.");
            return;
        }

        applyEmailStatus(data);
        showEmailInlineAlert(successMessage, "success");
        refreshEmailEvents();
    } catch (error) {
        applyEmailAgentError(`Email action failed: ${error.message}`);
    } finally {
        emailActionInFlight = false;
        updateEmailActionButtons();
    }
}

function updateEmailActionButtons() {
    const toggleButton = document.getElementById("toggleEmailScanBtn");
    const runOnceButton = document.getElementById("runEmailScanOnceBtn");
    const applyManualButton = document.getElementById("applyEmailManualConfigBtn");

    if (toggleButton) {
        toggleButton.disabled = emailActionInFlight;
    }
    if (runOnceButton) {
        runOnceButton.disabled = emailActionInFlight;
    }
    if (applyManualButton) {
        applyManualButton.disabled = emailActionInFlight;
    }
    setEmailToggleState(emailScannerEnabled);
}

function applyConnectionFields(connections, options = {}) {
    const force = !!options.force;
    if (!force && (isManualConfigEditing() || manualConfigDirty)) {
        return;
    }

    const hasMailpitHost = typeof connections.mailpit_host === "string" && connections.mailpit_host.trim() !== "";
    const hasMailpitPort = Number.isFinite(Number(connections.mailpit_port));
    const hasSmtpHost = typeof connections.smtp_host === "string" && connections.smtp_host.trim() !== "";
    const hasSmtpPort = Number.isFinite(Number(connections.smtp_port));

    if (hasMailpitHost) {
        setInputValue("emailManualHost", connections.mailpit_host);
    }
    if (hasMailpitPort) {
        setInputValue("emailManualPort", connections.mailpit_port);
    }
    if (hasSmtpHost) {
        setInputValue("emailManualSmtpHost", connections.smtp_host);
    }
    if (hasSmtpPort) {
        setInputValue("emailManualSmtpPort", connections.smtp_port);
    }
    manualConfigHydrated = true;
}

async function applyManualConnectionSettings() {
    if (!emailPageState || emailActionInFlight) return;

    const payload = {
        mailpit_host: getInputValue("emailManualHost", "localhost"),
        mailpit_port: getInputValue("emailManualPort", "8025"),
        smtp_host: getInputValue("emailManualSmtpHost", "localhost"),
        smtp_port: getInputValue("emailManualSmtpPort", "1025"),
    };

    emailActionInFlight = true;
    updateEmailActionButtons();

    try {
        const response = await fetch(emailPageState.dataset.configureManualUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            cache: "no-store",
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            applyEmailAgentError(data.error || "Failed to apply manual settings.");
            return;
        }

        manualConfigDirty = false;
        applyEmailStatus(data);
        applyConnectionFields(data.connections || {}, { force: true });
        setMailboxProviderNotice("Manual settings applied successfully.", "success");
        showEmailInlineAlert("Manual Mailpit/SMTP settings applied.", "success");
    } catch (error) {
        applyEmailAgentError(`Failed to apply manual settings: ${error.message}`);
    } finally {
        emailActionInFlight = false;
        updateEmailActionButtons();
    }
}

function initializeModuleInfoDialog() {
    const dialog = document.getElementById("moduleInfoDialog");
    const openButton = document.getElementById("moduleInfoBtn");
    const closeButton = document.getElementById("moduleInfoCloseBtn");

    if (!dialog || !openButton) return;

    openButton.addEventListener("click", () => {
        if (typeof dialog.showModal === "function") {
            dialog.showModal();
            dialog.style.inset = "0";
            dialog.style.margin = "auto";
        }
    });

    if (closeButton) {
        closeButton.addEventListener("click", () => dialog.close());
    }

    dialog.addEventListener("click", (event) => {
        const rect = dialog.getBoundingClientRect();
        const inside = (
            event.clientX >= rect.left &&
            event.clientX <= rect.right &&
            event.clientY >= rect.top &&
            event.clientY <= rect.bottom
        );
        if (!inside) {
            dialog.close();
        }
    });
}

function initializeMailboxConfigDialog() {
    const dialog = document.getElementById("mailboxConfigDialog");
    const openButton = document.getElementById("mailboxConfigBtn");
    const closeButton = document.getElementById("mailboxConfigCloseBtn");
    const outlookButton = document.getElementById("emailOutlookLoginBtn");
    const gmailButton = document.getElementById("emailGmailLoginBtn");
    const manualButton = document.getElementById("emailManualModeBtn");

    if (!dialog || !openButton) return;

    openButton.addEventListener("click", () => {
        if (typeof dialog.showModal === "function") {
            dialog.showModal();
            dialog.style.inset = "0";
            dialog.style.margin = "auto";
            setMailboxProviderNotice("Manual mode active. Update Host/Port and SMTP/Port, then apply.", "info");
        }
    });

    if (closeButton) {
        closeButton.addEventListener("click", () => dialog.close());
    }

    if (outlookButton) {
        outlookButton.addEventListener("click", () => {
            const message = "Outlook Login: Unavailable for demo.";
            setMailboxProviderNotice(message, "warning");
            showEmailInlineAlert(message, "warning");
        });
    }

    if (gmailButton) {
        gmailButton.addEventListener("click", () => {
            const message = "Gmail Login: Unavailable for demo.";
            setMailboxProviderNotice(message, "warning");
            showEmailInlineAlert(message, "warning");
        });
    }

    if (manualButton) {
        manualButton.addEventListener("click", () => {
            setMailboxProviderNotice("Manual mode active. Update Host/Port and SMTP/Port, then apply.", "info");
        });
    }

    dialog.addEventListener("click", (event) => {
        const rect = dialog.getBoundingClientRect();
        const inside = (
            event.clientX >= rect.left &&
            event.clientX <= rect.right &&
            event.clientY >= rect.top &&
            event.clientY <= rect.bottom
        );
        if (!inside) {
            dialog.close();
        }
    });
}

function initializeManualConfigInputTracking() {
    manualInputIds.forEach((id) => {
        const input = document.getElementById(id);
        if (!input) return;

        input.addEventListener("focus", () => {
            manualConfigFocusCount += 1;
        });

        input.addEventListener("blur", () => {
            manualConfigFocusCount = Math.max(0, manualConfigFocusCount - 1);
        });

        input.addEventListener("input", () => {
            manualConfigDirty = true;
        });
    });
}

function isManualConfigEditing() {
    return manualConfigFocusCount > 0;
}

function setMailboxProviderNotice(message, type = "info") {
    const notice = document.getElementById("mailboxProviderNotice");
    if (!notice) return;

    if (!message) {
        notice.style.display = "none";
        notice.textContent = "";
        notice.style.color = "";
        notice.style.background = "";
        notice.style.border = "";
        return;
    }

    let color = "#1f2937";
    let background = "#f3f4f6";
    let border = "#d1d5db";
    if (type === "warning") {
        color = "#92400e";
        background = "#fffbeb";
        border = "#fcd34d";
    } else if (type === "info") {
        color = "#1e3a8a";
        background = "#eff6ff";
        border = "#93c5fd";
    } else if (type === "success") {
        color = "#166534";
        background = "#ecfdf5";
        border = "#86efac";
    }

    notice.textContent = message;
    notice.style.display = "block";
    notice.style.padding = "8px 10px";
    notice.style.borderRadius = "6px";
    notice.style.color = color;
    notice.style.background = background;
    notice.style.border = `1px solid ${border}`;
}

async function refreshEmailEvents() {
    if (!emailPageState) return;

    const baseUrl = emailPageState.dataset.eventsUrl || "/api/events";
    const params = new URLSearchParams({
        limit: "50",
        module: "Email Analysis",
    });

    try {
        const response = await fetch(`${baseUrl}?${params.toString()}`, { cache: "no-store" });
        if (!response.ok) {
            return;
        }
        const events = await response.json();
        renderEmailEvents(Array.isArray(events) ? events : []);
    } catch (error) {
        console.debug("Email events refresh failed:", error);
    }
}

function renderEmailEvents(events) {
    const tableBody = document.getElementById("emailEventsTableBody");
    const countNode = document.getElementById("emailEventsCount");
    if (!tableBody) return;

    if (countNode) {
        countNode.textContent = String(events.length);
    }

    const normalizedEvents = Array.isArray(events) ? events : [];
    const fingerprint = normalizedEvents
        .map((event) => `${event.id || ""}|${event.timestamp || ""}|${event.status || ""}|${event.severity || ""}`)
        .join("||");
    if (fingerprint === lastEmailEventsFingerprint) {
        return;
    }
    lastEmailEventsFingerprint = fingerprint;

    if (!normalizedEvents.length) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" style="padding: 20px; text-align: center; color: #999;">
                    No email analysis events have been recorded yet.
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = normalizedEvents
        .map((event) => {
            const details = parseEventDetails(event.details);
            const title = details.subject || "-";
            const sender = details.sender || event.user_affected || "-";
            const eventJson = escapeHtml(JSON.stringify(event));

            return `
                <tr>
                    <td>${buildEmailSeverityPill(event.severity)}</td>
                    <td><div class="email-title-label" title="${escapeHtml(title)}">${escapeHtml(title)}</div></td>
                    <td><div class="email-threat-label" title="${escapeHtml(event.event_type || "-")}">${escapeHtml(event.event_type || "-")}</div></td>
                    <td><div class="email-sender-label" title="${escapeHtml(sender)}">${escapeHtml(sender)}</div></td>
                    <td><span class="email-time-label" title="${escapeHtml(event.timestamp || "-")}">${escapeHtml(formatEmailEventTime(event.timestamp))}</span></td>
                    <td>${buildEmailStatusPill(event.status)}</td>
                    <td>
                        <div class="email-event-actions">
                            <button type="button" class="btn btn-sm btn-info email-event-view-btn" data-event="${eventJson}">View</button>
                            ${buildEmailStatusActionForm(event)}
                        </div>
                    </td>
                </tr>
            `;
        })
        .join("");
}

function buildEmailSeverityPill(severityValue) {
    const severity = String(severityValue || "Low");
    const normalized = normalizeEmailToken(severity);
    const cssClass = ["high", "medium", "low"].includes(normalized) ? normalized : "info";
    return `
        <span class="email-severity-pill email-severity-${cssClass}">
            <span class="email-severity-dot"></span>${escapeHtml(severity)}
        </span>
    `;
}

function buildEmailStatusPill(statusValue) {
    const status = String(statusValue || "Open");
    const normalized = normalizeEmailToken(status);
    return `
        <span class="email-status-pill email-status-${escapeHtml(normalized)}">
            <span class="email-status-dot"></span>${escapeHtml(status)}
        </span>
    `;
}

function buildEmailStatusActionForm(event) {
    if (!event || !event.id) return "";

    if (event.status === "Open") {
        return `
            <form method="POST" action="/event/${event.id}/status">
                <input type="hidden" name="status" value="Acknowledged">
                <button type="submit" class="btn btn-sm email-ack-btn">Acknowledge</button>
            </form>
        `;
    }

    if (event.status === "Acknowledged") {
        return `
            <form method="POST" action="/event/${event.id}/status">
                <input type="hidden" name="status" value="Resolved">
                <button type="submit" class="btn btn-sm btn-success">Resolve</button>
            </form>
        `;
    }

    return "";
}

function normalizeEmailToken(value) {
    return String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "unknown";
}

function formatEmailEventTime(timestamp) {
    if (!timestamp) return "-";
    const parsed = new Date(timestamp);
    if (Number.isNaN(parsed.getTime())) {
        const match = String(timestamp).match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2})/);
        if (!match) return String(timestamp);
        const hour24 = Number(match[4]);
        const hour12 = hour24 % 12 || 12;
        const suffix = hour24 >= 12 ? "PM" : "AM";
        return `${match[3]}/${match[2]} ${hour12}:${match[5]}${suffix}`;
    }
    const day = String(parsed.getDate()).padStart(2, "0");
    const month = String(parsed.getMonth() + 1).padStart(2, "0");
    let hours = parsed.getHours();
    const minutes = String(parsed.getMinutes()).padStart(2, "0");
    const suffix = hours >= 12 ? "PM" : "AM";
    hours = hours % 12 || 12;
    return `${day}/${month} ${hours}:${minutes}${suffix}`;
}

function initializeEmailEventDetails() {
    const tableBody = document.getElementById("emailEventsTableBody");
    const dialog = document.getElementById("emailEventDetailDialog");
    const detectionButton = document.getElementById("emailEventDialogDetectionBtn");
    const closeButton = document.getElementById("emailEventDialogClose");
    const acknowledgeButton = document.getElementById("emailEventAcknowledgeBtn");
    const deleteAndBlockButton = document.getElementById("emailEventDeleteBlockBtn");
    const blockSenderButton = document.getElementById("emailEventBlockSenderBtn");
    const markSafeButton = document.getElementById("emailEventMarkSafeBtn");

    if (!tableBody || !dialog) return;

    tableBody.addEventListener("click", (event) => {
        const button = event.target.closest(".email-event-view-btn");
        if (!button) return;

        try {
            const eventData = JSON.parse(button.dataset.event || "{}");
            openEmailEventDetail(eventData);
        } catch (error) {
            console.debug("Could not open email event detail:", error);
        }
    });

    if (closeButton) {
        closeButton.addEventListener("click", () => dialog.close());
    }

    if (detectionButton) {
        detectionButton.addEventListener("click", () => toggleEmailDetectionSection());
    }

    if (acknowledgeButton) {
        acknowledgeButton.addEventListener("click", acknowledgeSelectedEmailEvent);
    }

    if (deleteAndBlockButton) {
        deleteAndBlockButton.addEventListener("click", deleteAndBlockSelectedEmailEvent);
    }

    if (blockSenderButton) {
        blockSenderButton.addEventListener("click", blockSenderForSelectedEmailEvent);
    }

    if (markSafeButton) {
        markSafeButton.addEventListener("click", markSelectedEmailEventSafe);
    }

    dialog.addEventListener("click", (event) => {
        if (event.target === dialog) {
            dialog.close();
        }
    });
}

function openEmailEventDetail(eventData) {
    const dialog = document.getElementById("emailEventDetailDialog");
    if (!dialog) return;
    selectedEmailEvent = eventData;

    const details = parseEventDetails(eventData.details);
    const title = details.subject || "-";
    const sender = details.sender || eventData.user_affected || "-";
    const riskScore = details.risk_score || details.score || details.risk || "-";
    const detectionReasons = parseDetectionReasons(details.reasons);

    setNodeHtml("emailEventDialogSeverity", buildEmailSeverityPill(eventData.severity));
    setNodeText("emailEventDialogTitle", eventData.event_type || "Email Event");
    setNodeText("emailEventDialogEmailTitle", title);
    setNodeText("emailEventDialogSender", sender);
    setNodeText("emailEventDialogUser", eventData.user_affected || "-");
    setNodeText("emailEventDialogTime", eventData.timestamp || "-");
    setNodeText("emailEventDialogRiskScore", riskScore);
    setNodeText("emailEventDialogThreatType", eventData.event_type || "-");
    setNodeText("emailEventDialogExplanation", eventData.explanation || "-");
    setNodeHtml("emailEventDialogRecommendation", formatMultilineText(eventData.recommendation || "-"));
    setNodeHtml("emailEventDialogDetectionReasons", buildEmailDetectionReasonsHtml(detectionReasons));

    setEmailDetectionSectionVisible(false);
    updateEmailEventActionButtons(eventData);

    if (typeof dialog.showModal === "function") {
        dialog.showModal();
        dialog.style.inset = "0";
        dialog.style.margin = "auto";
    } else {
        alert(`${eventData.event_type || "Email Event"}\n\n${eventData.explanation || ""}`);
    }
}

function updateEmailEventActionButtons(eventData) {
    const acknowledgeButton = document.getElementById("emailEventAcknowledgeBtn");
    const deleteAndBlockButton = document.getElementById("emailEventDeleteBlockBtn");
    const blockSenderButton = document.getElementById("emailEventBlockSenderBtn");
    const markSafeButton = document.getElementById("emailEventMarkSafeBtn");
    const status = normalizeEmailToken(eventData.status || "Open");
    const severity = normalizeEmailToken(eventData.severity || "Low");
    const isResolved = status === "resolved";
    const canContainThreat = severity === "high" || severity === "medium";

    if (acknowledgeButton) {
        acknowledgeButton.style.display = status === "open" ? "inline-block" : "none";
    }
    if (deleteAndBlockButton) {
        deleteAndBlockButton.style.display = !isResolved && canContainThreat ? "inline-block" : "none";
    }
    if (blockSenderButton) {
        blockSenderButton.style.display = !isResolved && canContainThreat ? "inline-block" : "none";
    }
    if (markSafeButton) {
        markSafeButton.style.display = !isResolved && severity === "medium" ? "inline-block" : "none";
    }
}

function toggleEmailDetectionSection() {
    const section = document.getElementById("emailEventDialogDetectionSection");
    if (!section) return;
    const isVisible = section.style.display !== "none";
    setEmailDetectionSectionVisible(!isVisible);
}

function setEmailDetectionSectionVisible(visible) {
    const section = document.getElementById("emailEventDialogDetectionSection");
    const detectionButton = document.getElementById("emailEventDialogDetectionBtn");

    if (section) {
        section.style.display = visible ? "block" : "none";
    }

    if (detectionButton) {
        detectionButton.classList.remove("btn-info", "btn-primary");
        detectionButton.classList.add(visible ? "btn-primary" : "btn-info");
        detectionButton.setAttribute("aria-expanded", visible ? "true" : "false");
    }
}

async function acknowledgeSelectedEmailEvent() {
    if (!selectedEmailEvent || !selectedEmailEvent.id) return;
    await runEmailEventAction(
        `/emailapi/events/${encodeURIComponent(selectedEmailEvent.id)}/acknowledge`,
        "Event acknowledged."
    );
}

async function deleteAndBlockSelectedEmailEvent() {
    if (!selectedEmailEvent || !selectedEmailEvent.id) return;

    const confirmed = confirm(
        "Delete this email from Mailpit and block the sender? This will resolve the event."
    );
    if (!confirmed) return;

    await runEmailEventAction(
        `/emailapi/events/${encodeURIComponent(selectedEmailEvent.id)}/delete-and-block`,
        "Email deleted, sender blocked, and event resolved."
    );
}

async function blockSenderForSelectedEmailEvent() {
    if (!selectedEmailEvent || !selectedEmailEvent.id) return;

    const confirmed = confirm(
        "Block this sender and delete this email from Mailpit? This will resolve the event."
    );
    if (!confirmed) return;

    await runEmailEventAction(
        `/emailapi/events/${encodeURIComponent(selectedEmailEvent.id)}/block-sender`,
        "Sender blocked, email deleted, and event resolved."
    );
}

async function markSelectedEmailEventSafe() {
    if (!selectedEmailEvent || !selectedEmailEvent.id) return;

    const confirmed = confirm(
        "Mark this email as safe? This will tag it as 'Marked Safe' and resolve the event."
    );
    if (!confirmed) return;

    await runEmailEventAction(
        `/emailapi/events/${encodeURIComponent(selectedEmailEvent.id)}/mark-safe`,
        "Email tagged as Marked Safe and event resolved."
    );
}

async function runEmailEventAction(url, successMessage) {
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
            cache: "no-store",
        });
        const data = await response.json();

        if (!response.ok || !data.success) {
            showEmailInlineAlert(data.error || "Email event action failed.", "danger");
            return;
        }

        const dialog = document.getElementById("emailEventDetailDialog");
        if (dialog && dialog.open) {
            dialog.close();
        }

        showEmailInlineAlert(successMessage, "success");
        refreshEmailEvents();
    } catch (error) {
        showEmailInlineAlert(`Action failed: ${error.message}`, "danger");
    }
}

function parseEventDetails(detailsValue) {
    const details = String(detailsValue || "");
    const output = {};
    details.split(";").forEach((part) => {
        const [rawKey, ...rest] = part.split("=");
        const key = String(rawKey || "").trim().toLowerCase();
        const value = rest.join("=").trim();
        if (key) {
            output[key] = value;
        }
    });
    return output;
}

function parseDetectionReasons(rawValue) {
    const raw = String(rawValue || "").trim();
    if (!raw) {
        return [];
    }

    const parsedJsonArray = parseArrayLikeValue(raw);
    if (parsedJsonArray.length) {
        return parsedJsonArray;
    }

    let normalized = raw;
    if (
        (normalized.startsWith("[") && normalized.endsWith("]")) ||
        (normalized.startsWith("(") && normalized.endsWith(")"))
    ) {
        normalized = normalized.slice(1, -1);
    }

    return normalized
        .split(/\r?\n|\||,/)
        .map((part) => String(part || "").trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
}

function parseArrayLikeValue(value) {
    try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) {
            return parsed.map((item) => String(item || "").trim()).filter(Boolean);
        }
    } catch (_error) {
        // Ignore and continue with permissive parsing.
    }

    const singleQuoted = value.replace(/'/g, "\"");
    try {
        const parsed = JSON.parse(singleQuoted);
        if (Array.isArray(parsed)) {
            return parsed.map((item) => String(item || "").trim()).filter(Boolean);
        }
    } catch (_error) {
        // Ignore and continue with delimiter parsing.
    }

    return [];
}

function buildEmailDetectionReasonsHtml(reasons) {
    if (!Array.isArray(reasons) || !reasons.length) {
        return "No detection reasons available.";
    }

    const items = reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
    return `<ul class="email-event-detection-list">${items}</ul>`;
}

function formatMultilineText(value) {
    return escapeHtml(value).replace(/\n/g, "<br>");
}

function setNodeText(id, value) {
    const node = document.getElementById(id);
    if (node) {
        node.textContent = String(value);
    }
}

function setNodeHtml(id, html) {
    const node = document.getElementById(id);
    if (node) {
        node.innerHTML = html;
    }
}

function applyEmailAgentError(message) {
    const node = document.getElementById("emailAgentError");
    if (!node) return;

    if (message) {
        node.textContent = message;
        node.style.display = "block";
    } else {
        node.textContent = "";
        node.style.display = "none";
    }
}

function setInputValue(id, value) {
    const node = document.getElementById(id);
    if (node) {
        node.value = String(value);
    }
}

function getInputValue(id, fallback = "") {
    const node = document.getElementById(id);
    if (!node) return fallback;
    const value = String(node.value || "").trim();
    return value || fallback;
}

function formatTimestamp(value) {
    if (!value) return "-";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return String(value);
    }
    return parsed.toLocaleString();
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function showEmailInlineAlert(message, type = "info") {
    const pageHeader = document.querySelector(".page-header");
    if (!pageHeader || !message) return;

    const alertDiv = document.createElement("div");
    alertDiv.className = `alert alert-${type}`;
    alertDiv.style.marginTop = "12px";
    alertDiv.innerHTML = `${escapeHtml(message)} <button class="close-btn" onclick="this.parentElement.remove()">&times;</button>`;
    pageHeader.insertAdjacentElement("afterend", alertDiv);

    setTimeout(() => {
        if (alertDiv && alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 4000);
}
