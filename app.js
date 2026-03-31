const PROXIES_URL = 'proxies.json';
let allProxies = [];
let filteredProxies = [];

// Загрузка прокси
async function loadProxies() {
    try {
        const response = await fetch(PROXIES_URL + '?t=' + Date.now());
        const data = await response.json();
        allProxies = data.proxies || [];
        updateLastUpdate(data.last_update);
        updateTotalProxies(allProxies.length);
        populateCountryFilter();
        filteredProxies = [...allProxies];
        renderProxies();
    } catch (error) {
        document.getElementById('proxy-list').innerHTML = 
            `<div class="no-proxies">Ошибка загрузки: ${error.message}</div>`;
    }
}

// Обновление времени последнего обновления
function updateLastUpdate(timestamp) {
    const date = new Date(timestamp * 1000);
    document.getElementById('last-update').textContent = 
        'Обновлено: ' + date.toLocaleString('ru-RU', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
}

// Обновление количества прокси
function updateTotalProxies(count) {
    document.getElementById('total-proxies').textContent = `Всего: ${count}`;
}

// Заполнение фильтра стран
function populateCountryFilter() {
    const countries = [...new Set(allProxies.map(p => p.country).filter(Boolean))];
    const select = document.getElementById('country-filter');
    select.innerHTML = '<option value="">Все страны</option>';
    
    countries.sort().forEach(country => {
        const option = document.createElement('option');
        option.value = country;
        option.textContent = country;
        select.appendChild(option);
    });
}

// Рендеринг списка прокси
function renderProxies() {
    const container = document.getElementById('proxy-list');
    
    if (filteredProxies.length === 0) {
        container.innerHTML = '<div class="no-proxies">Прокси не найдено</div>';
        return;
    }
    
    container.innerHTML = filteredProxies.map(proxy => `
        <div class="proxy-card ${getStatusClass(proxy.ping)}" data-proxy='${JSON.stringify(proxy)}'>
            <div class="proxy-header">
                <span class="proxy-country">${proxy.flag || '🌐'} ${proxy.country || 'Неизвестно'}</span>
                <span class="proxy-status"></span>
            </div>
            <div class="proxy-info">
                <div class="proxy-info-row">
                    <span>IP:</span>
                    <span>${proxy.ip}</span>
                </div>
                <div class="proxy-info-row">
                    <span>Порт:</span>
                    <span>${proxy.port}</span>
                </div>
                <div class="proxy-info-row">
                    <span>Пинг:</span>
                    <span class="proxy-ping">${formatPing(proxy.ping)}</span>
                </div>
            </div>
        </div>
    `).join('');
    
    // Добавляем обработчики кликов
    container.querySelectorAll('.proxy-card').forEach(card => {
        card.addEventListener('click', () => {
            const proxy = JSON.parse(card.dataset.proxy);
            openModal(proxy);
        });
    });
}

// Форматирование пинга
function formatPing(ping) {
    if (ping === null || ping === undefined) return '--';
    if (ping < 100) return `${ping} ms ✓`;
    if (ping < 300) return `${ping} ms ⚠`;
    return `${ping} ms ✗`;
}

// Класс статуса
function getStatusClass(ping) {
    if (ping === null || ping === undefined) return '';
    if (ping < 100) return '';
    if (ping < 300) return 'status-warning';
    return 'status-error';
}

// Открытие модального окна
function openModal(proxy) {
    const modal = document.getElementById('modal');
    const link = generateProxyLink(proxy);
    
    document.getElementById('detail-country').textContent = `${proxy.flag || '🌐'} ${proxy.country || 'Неизвестно'}`;
    document.getElementById('detail-ip').textContent = proxy.ip;
    document.getElementById('detail-port').textContent = proxy.port;
    document.getElementById('detail-secret').textContent = proxy.secret;
    document.getElementById('detail-ping').textContent = formatPing(proxy.ping);
    document.getElementById('detail-link').value = link;
    
    const connectLink = document.getElementById('connect-link');
    connectLink.href = link;
    
    modal.classList.add('active');
}

// Генерация ссылки tg://proxy
function generateProxyLink(proxy) {
    return `tg://proxy?server=${proxy.ip}&port=${proxy.port}&secret=${proxy.secret}`;
}

// Закрытие модального окна
function closeModal() {
    document.getElementById('modal').classList.remove('active');
}

// Копирование ссылки
function copyLink() {
    const linkInput = document.getElementById('detail-link');
    linkInput.select();
    document.execCommand('copy');
    
    const copyBtn = document.getElementById('copy-link');
    const originalText = copyBtn.textContent;
    copyBtn.textContent = 'Скопировано!';
    setTimeout(() => {
        copyBtn.textContent = originalText;
    }, 2000);
}

// Фильтрация
function applyFilters() {
    const searchTerm = document.getElementById('search-input').value.toLowerCase();
    const countryFilter = document.getElementById('country-filter').value;
    
    filteredProxies = allProxies.filter(proxy => {
        const matchesSearch = searchTerm === '' || 
            proxy.ip.toLowerCase().includes(searchTerm) ||
            (proxy.country && proxy.country.toLowerCase().includes(searchTerm));
        
        const matchesCountry = countryFilter === '' || proxy.country === countryFilter;
        
        return matchesSearch && matchesCountry;
    });
    
    renderProxies();
}

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    loadProxies();
    
    // Обработчики
    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('modal').addEventListener('click', (e) => {
        if (e.target.id === 'modal') closeModal();
    });
    document.getElementById('copy-link').addEventListener('click', copyLink);
    document.getElementById('refresh-btn').addEventListener('click', loadProxies);
    document.getElementById('search-input').addEventListener('input', applyFilters);
    document.getElementById('country-filter').addEventListener('change', applyFilters);
    
    // Автообновление каждые 5 минут
    setInterval(loadProxies, 5 * 60 * 1000);
});
