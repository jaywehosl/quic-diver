package store

import (
	"fmt"
	"time"
)

// Слепок расхода на диске.
//
// # Почему это не статичная база
//
// Расход — динамика: он растёт постоянно, не подписан, не расходится журналом и не попадает
// в выгрузку. На диск он ложится ровно за одним: лимит «пятьдесят гигабайт в месяц» обязан
// пережить перезапуск узла. Счётчик, живущий только в памяти, обнулялся бы при каждом
// обновлении — и лимит превращался бы в пожелание.
//
// # Почему только своя ячейка
//
// Чужие ячейки G-Counter хранить незачем: они приедут от соседей заново через несколько
// секунд после запуска. Своя же не приедет ниоткуда — её знаем только мы.

// UsageCell — одна ячейка расхода: клиент за расчётный период.
type UsageCell struct {
	Client   string
	Period   string
	Sent     uint64
	Received uint64
}

const usageSchema = `
CREATE TABLE IF NOT EXISTS usage (
	client     TEXT    NOT NULL,
	period     TEXT    NOT NULL,
	sent       INTEGER NOT NULL,
	received   INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (client, period)
) STRICT;
`

// SaveUsage сохраняет свои ячейки расхода.
//
// Пишется всё разом и в одной сделке: половина сохранённого расхода хуже несохранённого —
// по ней нельзя понять, чему верить.
func (s *Store) SaveUsage(cells []UsageCell) error {
	if len(cells) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: сохранение расхода: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO usage (client, period, sent, received, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (client, period) DO UPDATE SET
			sent = excluded.sent,
			received = excluded.received,
			updated_at = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("store: сохранение расхода: %w", err)
	}
	defer stmt.Close()

	now := time.Now().UnixMilli()
	for _, c := range cells {
		if _, err := stmt.Exec(c.Client, c.Period, int64(c.Sent), int64(c.Received), now); err != nil {
			return fmt.Errorf("store: расход %s/%s: %w", c.Client, c.Period, err)
		}
	}
	return tx.Commit()
}

// LoadUsage читает сохранённые ячейки.
func (s *Store) LoadUsage() ([]UsageCell, error) {
	rows, err := s.db.Query(`SELECT client, period, sent, received FROM usage`)
	if err != nil {
		return nil, fmt.Errorf("store: чтение расхода: %w", err)
	}
	defer rows.Close()

	var out []UsageCell
	for rows.Next() {
		var (
			c              UsageCell
			sent, received int64
		)
		if err := rows.Scan(&c.Client, &c.Period, &sent, &received); err != nil {
			return nil, fmt.Errorf("store: чтение расхода: %w", err)
		}
		c.Sent, c.Received = uint64(sent), uint64(received)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ForgetUsageBefore выбрасывает ячейки старых расчётных периодов.
//
// Иначе таблица растёт вечно: у клиента с месячным лимитом каждый месяц заводит новую строку,
// а старые не нужны никому — лимит смотрит только на текущий период.
func (s *Store) ForgetUsageBefore(t time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM usage WHERE updated_at < ?`, t.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("store: чистка расхода: %w", err)
	}
	return res.RowsAffected()
}
