# MTProto Proxy List

Экспериментальный репозиторий со списком активных MTProto-прокси для Telegram.

## Что делает проект

- собирает прокси из нескольких открытых источников
- очищает и нормализует данные
- проверяет доступность прокси
- определяет страну по IP
- сохраняет результат в `proxies.json`
- показывает список на статическом сайте

## Структура проекта

```text
├── index.html                  # Главная страница
├── styles.css                  # Стили
├── app.js                      # Логика фронтенда
├── main.py                     # Основная точка входа
├── proxies.json                # Сгенерированный список прокси
├── modules/                    # Модульное ядро проекта
│   ├── cli.py
│   ├── pipeline.py
│   ├── parsers.py
│   ├── checker.py
│   ├── metadata.py
│   ├── geo.py
│   ├── sources.py
│   ├── config.py
│   └── models.py
└── .github/workflows/
    └── check-proxies.yml       # Автообновление списка
```

## Локальный запуск

```bash
python main.py
```

## GitHub Actions

Workflow запускает:

```bash
python main.py
```

После успешной генерации workflow валидирует `proxies.json`, собирает статический сайт и
публикует его через GitHub Pages artifact без push в основную ветку.

## Лицензия

MIT
