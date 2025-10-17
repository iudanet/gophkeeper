# TODO - Будущие улучшения GophKeeper

## Приоритетные задачи

### 1. Смена мастер-пароля
- [ ] Реализовать команду `gophkeeper change-password`
- [ ] API endpoint `POST /api/v1/auth/change-password`
- [ ] Создание backup перед операцией
- [ ] Расшифровка всех данных старым ключом
- [ ] Генерация новой соли и ключей
- [ ] Перешифрование всех данных новым ключом
- [ ] Атомарная транзакция (rollback при ошибке)
- [ ] Синхронизация с сервером
- [ ] Обновление AuthKeyHash на сервере

**Проблемы для решения:**
- Обработка больших объемов данных
- Синхронизация на всех устройствах пользователя
- Безопасность промежуточного состояния

### 2. Переезд на Cobra для CLI
- [ ] Заменить `flag` на `github.com/spf13/cobra`
- [ ] Заменить `flag` на `github.com/spf13/viper` для конфигурации
- [ ] Реорганизовать структуру команд
- [ ] Добавить subcommands с nested флагами
- [ ] Улучшить help messages
- [ ] Добавить shell автодополнение (bash, zsh, fish)

**Преимущества:**
- Более чистая структура команд
- Встроенное автодополнение
- Лучшая документация команд
- Стандарт в Go экосистеме

### 3. TUI (Terminal User Interface)
- [ ] Интеграция `github.com/charmbracelet/bubbletea`
- [ ] Команда `gophkeeper tui` для запуска интерактивного режима
- [ ] Навигация по списку записей (стрелки/vim keys)
- [ ] Просмотр деталей записи
- [ ] Добавление/редактирование/удаление через формы
- [ ] Поиск в реальном времени (fuzzy search)
- [ ] Древовидное отображение по категориям
- [ ] Горячие клавиши (?, h - help, q - quit, / - search)
- [ ] Copy to clipboard для паролей
- [ ] Цветовое кодирование по типам данных

**UI компоненты:**
- List view для всех записей
- Detail view для просмотра
- Form view для редактирования
- Search bar с фильтрами
- Status bar с информацией о синхронизации

### 4. JSON вывод
- [ ] Глобальный флаг `--output json` (или `-o json`)
- [ ] Форматирование всех команд в JSON
- [ ] Поддержка `--pretty` для human-readable JSON
- [ ] Структурированный вывод ошибок в JSON
- [ ] Примеры использования в README

**Команды с JSON выводом:**
```bash
gophkeeper list credentials --output json
gophkeeper get <id> --output json
gophkeeper status --output json
gophkeeper sync --output json
```

**Формат JSON:**
```json
{
  "status": "success",
  "data": {
    "credentials": [
      {
        "id": "uuid",
        "name": "GitHub",
        "login": "user@example.com",
        "url": "https://github.com"
      }
    ]
  },
  "meta": {
    "count": 1,
    "timestamp": "2025-10-17T12:30:45Z"
  }
}
```
