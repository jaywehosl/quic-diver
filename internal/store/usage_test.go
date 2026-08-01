package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func openUsageStore(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := Open(filepath.Join(dir, "oplog.db"), oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	return st
}

// Расход обязан пережить перезапуск: без этого лимит за месяц обнулялся бы при каждом
// обновлении узла.
func TestUsageSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	st := openUsageStore(t, dir)
	err := st.SaveUsage([]UsageCell{
		{Client: "vasya", Period: "2026-07", Sent: 1000, Received: 50_000_000},
		{Client: "petya", Period: "", Sent: 7, Received: 9},
	})
	if err != nil {
		t.Fatalf("сохранение: %v", err)
	}
	st.Close()

	// Узел перезапустился.
	st = openUsageStore(t, dir)
	defer st.Close()

	cells, err := st.LoadUsage()
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(cells) != 2 {
		t.Fatalf("ячеек: %d", len(cells))
	}

	byClient := make(map[string]UsageCell, len(cells))
	for _, c := range cells {
		byClient[c.Client] = c
	}
	if got := byClient["vasya"]; got.Received != 50_000_000 || got.Period != "2026-07" {
		t.Fatalf("расход vasya не тот: %+v", got)
	}
	if got := byClient["petya"]; got.Sent != 7 || got.Period != "" {
		t.Fatalf("расход petya не тот: %+v", got)
	}
}

// Повторное сохранение заменяет, а не плодит строки.
func TestUsageOverwrites(t *testing.T) {
	st := openUsageStore(t, t.TempDir())
	defer st.Close()

	cell := UsageCell{Client: "vasya", Period: "2026-07", Sent: 10, Received: 20}
	if err := st.SaveUsage([]UsageCell{cell}); err != nil {
		t.Fatalf("сохранение: %v", err)
	}

	cell.Sent, cell.Received = 100, 200
	if err := st.SaveUsage([]UsageCell{cell}); err != nil {
		t.Fatalf("пересохранение: %v", err)
	}

	cells, err := st.LoadUsage()
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(cells) != 1 {
		t.Fatalf("строк: %d, а ячейка одна", len(cells))
	}
	if cells[0].Sent != 100 || cells[0].Received != 200 {
		t.Fatalf("значение не обновилось: %+v", cells[0])
	}
}

// Старые периоды выбрасываются: иначе таблица растёт вечно.
func TestUsageForgetsOldPeriods(t *testing.T) {
	st := openUsageStore(t, t.TempDir())
	defer st.Close()

	if err := st.SaveUsage([]UsageCell{{Client: "vasya", Period: "2026-01", Sent: 1, Received: 1}}); err != nil {
		t.Fatalf("сохранение: %v", err)
	}

	n, err := st.ForgetUsageBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("чистка: %v", err)
	}
	if n != 1 {
		t.Fatalf("выброшено строк: %d", n)
	}

	cells, err := st.LoadUsage()
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("после чистки осталось %d строк", len(cells))
	}
}

// Расход не попадает в выгрузку журнала: это динамика, а не подписанные записи.
func TestUsageStaysOutOfExport(t *testing.T) {
	st := openUsageStore(t, t.TempDir())
	defer st.Close()

	if err := st.SaveUsage([]UsageCell{{Client: "vasya", Period: "", Sent: 42, Received: 42}}); err != nil {
		t.Fatalf("сохранение: %v", err)
	}

	var out testWriter
	if err := st.Export(&out); err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	if len(out.b) != 0 {
		t.Fatalf("в выгрузке %d байт, а записей журнала нет", len(out.b))
	}
}

type testWriter struct{ b []byte }

func (w *testWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}
