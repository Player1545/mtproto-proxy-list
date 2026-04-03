const PROXIES_URL = "proxies.json";
let allProxies = [];
let filteredProxies = [];
let activeSecret = "";
let isSecretExpanded = false;
let currentPage = 1;

const PAGE_SIZE = 60;

// Загрузка и подготовка данных.
async function loadProxies() {
    showStatus("Загрузка прокси...", "loading");

    try {
        const response = await fetch(`${PROXIES_URL}?t=${Date.now()}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (!data || !Array.isArray(data.proxies)) {
            throw new Error("Некорректный формат данных");
        }

        allProxies = data.proxies;
        filteredProxies = [...allProxies];
        currentPage = 1;

        updateLastUpdate(data.last_update);
        updateTotalProxies(allProxies.length);
        populateCountryFilter();
        renderProxies();
    } catch (error) {
        allProxies = [];
        filteredProxies = [];
        currentPage = 1;
        updateLastUpdate(null);
        updateTotalProxies(0);
        populateCountryFilter();
        showStatus(`Не удалось загрузить список прокси: ${error.message}`, "no-proxies");
    }
}

function updateLastUpdate(timestamp) {
    const target = document.getElementById("last-update");
    if (!timestamp) {
        target.textContent = "Обновлено: --";
        return;
    }

    const date = new Date(timestamp * 1000);
    target.textContent = `Обновлено: ${date.toLocaleString("ru-RU", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    })}`;
}

function updateTotalProxies(count) {
    document.getElementById("total-proxies").textContent = `Всего: ${count}`;
}

function populateCountryFilter() {
    const countries = [...new Set(allProxies.map((proxy) => proxy.country).filter(Boolean))];
    const select = document.getElementById("country-filter");
    select.innerHTML = "";

    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = "Все страны";
    select.appendChild(defaultOption);

    countries.sort().forEach((country) => {
        const option = document.createElement("option");
        option.value = country;
        option.textContent = country;
        select.appendChild(option);
    });
}

// Рендер списка прокси.
function renderProxies() {
    const container = document.getElementById("proxy-list");
    container.innerHTML = "";

    if (filteredProxies.length === 0) {
        showStatus("Прокси не найдено", "no-proxies");
        renderPagination();
        return;
    }

    const pageItems = getPaginatedProxies();
    const fragment = document.createDocumentFragment();
    pageItems.forEach((proxy) => {
        fragment.appendChild(createProxyCard(proxy));
    });
    container.appendChild(fragment);
    renderPagination();
}

function createProxyCard(proxy) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = `proxy-card ${getStatusClass(proxy.ping)}`.trim();

    const header = document.createElement("div");
    header.className = "proxy-header";

    const country = document.createElement("span");
    country.className = "proxy-country";
    country.textContent = `${proxy.flag || "🌐"} ${proxy.country || "Неизвестно"}`;

    const status = document.createElement("span");
    status.className = "proxy-status";
    status.setAttribute("aria-hidden", "true");
    header.append(country, status);

    if (proxy.is_fake_tls) {
        card.appendChild(createFakeTlsBadge(proxy.fake_tls_domain));
    }

    const info = document.createElement("div");
    info.className = "proxy-info";
    info.append(
        createInfoRow("IP:", proxy.ip),
        createInfoRow("Порт:", proxy.port),
        createInfoRow("Пинг:", formatPing(proxy.ping), "proxy-ping"),
    );

    card.append(header, info);
    card.addEventListener("click", () => openModal(proxy));
    return card;
}

function createFakeTlsBadge(domain) {
    const badge = document.createElement("div");
    badge.className = "proxy-badge";
    badge.textContent = domain ? `Fake TLS: ${domain}` : "Fake TLS";
    return badge;
}

function createInfoRow(label, value, valueClass = "") {
    const row = document.createElement("div");
    row.className = "proxy-info-row";

    const labelElement = document.createElement("span");
    labelElement.textContent = label;

    const valueElement = document.createElement("span");
    valueElement.textContent = String(value);
    if (valueClass) {
        valueElement.className = valueClass;
    }

    row.append(labelElement, valueElement);
    return row;
}

function showStatus(message, className) {
    const container = document.getElementById("proxy-list");
    container.innerHTML = "";

    const state = document.createElement("div");
    state.className = className;
    state.textContent = message;
    container.appendChild(state);
}

function getPaginatedProxies() {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filteredProxies.slice(start, start + PAGE_SIZE);
}

function getTotalPages() {
    return Math.max(1, Math.ceil(filteredProxies.length / PAGE_SIZE));
}

function renderPagination() {
    const pagination = document.getElementById("pagination");
    pagination.innerHTML = "";

    if (filteredProxies.length <= PAGE_SIZE) {
        pagination.hidden = true;
        return;
    }

    pagination.hidden = false;

    const totalPages = getTotalPages();
    const info = document.createElement("span");
    info.className = "pagination-info";

    const start = (currentPage - 1) * PAGE_SIZE + 1;
    const end = Math.min(currentPage * PAGE_SIZE, filteredProxies.length);
    info.textContent = `${start}-${end} из ${filteredProxies.length}`;

    const prevButton = createPaginationButton("Назад", currentPage === 1, () => {
        currentPage -= 1;
        renderProxies();
    });

    const nextButton = createPaginationButton("Вперед", currentPage === totalPages, () => {
        currentPage += 1;
        renderProxies();
    });

    const pageLabel = document.createElement("span");
    pageLabel.className = "pagination-page";
    pageLabel.textContent = `Страница ${currentPage} / ${totalPages}`;

    pagination.append(prevButton, pageLabel, nextButton, info);
}

function createPaginationButton(label, disabled, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "pagination-btn";
    button.textContent = label;
    button.disabled = disabled;
    if (!disabled) {
        button.addEventListener("click", onClick);
    }
    return button;
}

// Форматирование и отображение значений.
function formatPing(ping) {
    if (ping === null || ping === undefined) return "--";
    if (ping < 100) return `${ping} ms ✓`;
    if (ping < 300) return `${ping} ms ⚠`;
    return `${ping} ms ✗`;
}

function getStatusClass(ping) {
    if (ping === null || ping === undefined) return "";
    if (ping < 100) return "";
    if (ping < 300) return "status-warning";
    return "status-error";
}

function formatSecret(secret, expanded = false) {
    if (!secret) return "--";
    if (expanded || secret.length <= 48) return secret;
    return `${secret.slice(0, 12)}...${secret.slice(-8)}`;
}

function updateSecretDisplay() {
    const secretElement = document.getElementById("detail-secret");
    const toggleButton = document.getElementById("toggle-secret");

    secretElement.textContent = formatSecret(activeSecret, isSecretExpanded);
    secretElement.title = activeSecret || "";

    if (!activeSecret || activeSecret.length <= 48) {
        toggleButton.hidden = true;
        return;
    }

    toggleButton.hidden = false;
    toggleButton.textContent = isSecretExpanded ? "Скрыть" : "Показать полностью";
}

// Модальное окно с деталями прокси.
function openModal(proxy) {
    const modal = document.getElementById("modal");
    const link = generateProxyLink(proxy);

    document.getElementById("detail-country").textContent =
        `${proxy.flag || "🌐"} ${proxy.country || "Неизвестно"}`;
    document.getElementById("detail-ip").textContent = proxy.ip;
    document.getElementById("detail-port").textContent = proxy.port;
    document.getElementById("detail-ping").textContent = formatPing(proxy.ping);
    document.getElementById("detail-link").value = link;
    document.getElementById("connect-link").href = link;
    updateProxyType(proxy);

    activeSecret = proxy.secret || "";
    isSecretExpanded = false;
    updateSecretDisplay();
    modal.classList.add("active");
}

function updateProxyType(proxy) {
    const typeElement = document.getElementById("detail-type");
    const domainElement = document.getElementById("detail-fake-domain");
    const domainRow = document.getElementById("fake-domain-row");

    if (proxy.is_fake_tls) {
        typeElement.textContent = "Fake TLS";
        if (proxy.fake_tls_domain) {
            domainElement.textContent = proxy.fake_tls_domain;
            domainRow.hidden = false;
        } else {
            domainElement.textContent = "--";
            domainRow.hidden = true;
        }
        return;
    }

    typeElement.textContent = "Обычный MTProto";
    domainElement.textContent = "--";
    domainRow.hidden = true;
}

function generateProxyLink(proxy) {
    return `tg://proxy?server=${proxy.ip}&port=${proxy.port}&secret=${proxy.secret}`;
}

function closeModal() {
    document.getElementById("modal").classList.remove("active");
}

// Действия пользователя.
async function copyLink() {
    const linkInput = document.getElementById("detail-link");
    const value = linkInput.value;
    const copyButton = document.getElementById("copy-link");
    const originalText = copyButton.textContent;

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(value);
        } else {
            linkInput.select();
            document.execCommand("copy");
        }

        copyButton.textContent = "Скопировано!";
    } catch (error) {
        copyButton.textContent = "Ошибка копирования";
    }

    setTimeout(() => {
        copyButton.textContent = originalText;
    }, 2000);
}

function applyFilters() {
    const searchTerm = document.getElementById("search-input").value.toLowerCase().trim();
    const countryFilter = document.getElementById("country-filter").value;

    filteredProxies = allProxies.filter((proxy) => {
        const matchesSearch =
            searchTerm === "" ||
            String(proxy.ip || "").toLowerCase().includes(searchTerm) ||
            String(proxy.country || "").toLowerCase().includes(searchTerm);

        const matchesCountry = countryFilter === "" || proxy.country === countryFilter;
        return matchesSearch && matchesCountry;
    });

    currentPage = 1;
    renderProxies();
}

// Инициализация обработчиков и автообновления.
document.addEventListener("DOMContentLoaded", () => {
    loadProxies();

    document.getElementById("modal-close").addEventListener("click", closeModal);
    document.getElementById("modal").addEventListener("click", (event) => {
        if (event.target.id === "modal") {
            closeModal();
        }
    });
    document.getElementById("copy-link").addEventListener("click", copyLink);
    document.getElementById("toggle-secret").addEventListener("click", () => {
        isSecretExpanded = !isSecretExpanded;
        updateSecretDisplay();
    });
    document.getElementById("refresh-btn").addEventListener("click", loadProxies);
    document.getElementById("search-input").addEventListener("input", applyFilters);
    document.getElementById("country-filter").addEventListener("change", applyFilters);
    setInterval(loadProxies, 5 * 60 * 1000);
});
