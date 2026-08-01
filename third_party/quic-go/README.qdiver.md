# quic-go внутри QUIC Diver

Это **форк** `github.com/quic-go/quic-go`, а не зависимость. Подключён через `replace` в
корневом `go.mod`.

- Точка ветвления: **v0.61.0**, дерево скопировано без изменений.
- Выброшено при копировании: `.github/`, `.clusterfuzzlite/`, `.githooks/` — чужой CI нам не нужен
  и только шумит в diff.

## Зачем форк

Congestion control в quic-go не подменяется снаружи: интерфейс `SendAlgorithm` объявлен в
`internal/congestion/interface.go`, в `quic.Config` поля под него нет, а `NewCubicSender`
зашит прямо в `internal/ackhandler/sent_packet_handler.go`. BRUTAL без правки библиотеки
невозможен — проверено чтением дерева, а не по памяти.

## Правила работы с форком

1. **Каждое отличие от апстрима — отдельный коммит с префиксом `fork:`** и объяснением, что и
   зачем изменено. Иначе через полгода никто не соберёт список наших правок.
2. Патч держим минимальным и локальным. Ничего «заодно причесать».
3. Версия апстрима пинится. Апгрейд — вручную, с прогоном `integrationtests/self`.
4. Апстримные тесты не удаляем: они и есть проверка того, что патч ничего не сломал.

## Список наших правок

### 1. BRUTAL — контроль перегрузки с заданной скоростью

Решение [006](../../docs/decisions/006-brutal.md). Отклонение от RFC 9002 §7 описано там же.

| Файл | Что |
|---|---|
| `internal/congestion/brutal.go` | новый файл: сам алгоритм |
| `internal/congestion/brutal_test.go` | новый файл: его проверки |
| `internal/ackhandler/sent_packet_handler.go` | `newCongestionController` выбирает алгоритм; поле `brutalSendMbps` переживает переезд на другой путь |
| `interface.go` | поле `Config.BrutalSendMbps` |
| `config.go` | перенос поля в `populateConfig` |
| `connection.go` | проброс в `NewSentPacketHandler` (два места) |
| `internal/ackhandler/sent_packet_handler_test.go` | новый аргумент в 21 вызове |
| `config_test.go` | новое поле в списке учтённых |

Нулевая скорость означает, что ничего не меняется и работает стандартный Cubic. Апстримные
тесты правились только по форме вызовов; ни один не выключен и не ослаблен.
