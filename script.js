const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const result = document.querySelector("#result");
const sampleButton = document.querySelector(".sample");

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function renderResult(data) {
    const findings = data.findings
        .map((item) => `
            <li class="finding ${escapeHtml(item.risk)}">
                <strong>${escapeHtml(item.label)}</strong>
                <span>${escapeHtml(item.detail)}</span>
            </li>
        `)
        .join("");

    result.className = "result";
    result.innerHTML = `
        <div class="result-header">
            <div>
                <h2 class="status">${escapeHtml(data.status)}</h2>
                <p class="domain">Domain checked: ${escapeHtml(data.domain)}</p>
            </div>
            <div class="score ${escapeHtml(data.level)}">${escapeHtml(data.score)}%</div>
        </div>
        <ul class="findings">${findings}</ul>
    `;
}

function renderError(message) {
    result.className = "result";
    result.innerHTML = `<p class="error">${escapeHtml(message)}</p>`;
}

async function scanUrl(url) {
    result.className = "result";
    result.innerHTML = `<p class="empty-title">Scanning...</p>`;

    try {
        const response = await fetch("/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Unable to scan this URL.");
        }

        renderResult(data);
    } catch (error) {
        renderError(error.message);
    }
}

form.addEventListener("submit", (event) => {
    event.preventDefault();
    scanUrl(input.value);
});

sampleButton.addEventListener("click", () => {
    input.value = sampleButton.dataset.url;
    scanUrl(input.value);
});
