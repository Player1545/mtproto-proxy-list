# MTProto Proxy List
P.S. Это эксперемнтальный репозиторий, созданный при помощи Qwen (coder-model).
Список активных MTProto прокси для Telegram.

## Особенности

- ✅ Автоматический парсинг из 3 источников
- ✅ Проверка доступности прокси каждые 3 часа
- ✅ Определение страны по IP
- ✅ Очистка ссылок от рекламных параметров
- ✅ Сортировка по пингу

## Источники прокси

1. [V2RayRoot/V2RayConfig](https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/proxies.txt)
2. [sakha1370/V2rayCollector](https://raw.githubusercontent.com/sakha1370/V2rayCollector/refs/heads/main/active_mtproto_proxies.txt)
3. [WhitePrime/xraycheck](https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/white-list_mtproto)

## Структура проекта

```
├── index.html              # Главная страница
├── styles.css              # Стили
├── app.js                  # Фронтенд логика
├── check_proxies.py        # Скрипт проверки прокси
├── proxies.json            # Результат проверки (генерируется автоматически)
└── .github/
    └── workflows/
        └── check-proxies.yml  # GitHub Actions workflow
```

## Локальный запуск проверки

```bash
python check_proxies.py
```

## Лицензия

MIT
