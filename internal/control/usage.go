package control

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/jaywehosl/quic-diver/internal/ledger"
)

// Обмен динамической базой: счётчики трафика и живые сессии (решение 001 §2).
//
// В отличие от журнала, тут ничего не подписывается: данные и так приходят от опознанного
// соседа по установленному каналу, а подделать их он мог бы и с подписью — считает-то он сам.
// Защита здесь другая и лежит в самой модели: свою ячейку счётчика узел пишет только сам, и
// чужие значения её не трогают.

// ExchangeUsage обменивается картиной с соседом.
//
// Симметрично и одновременно, ровно по той же причине, что и обмен журналом: обе стороны
// начинают с отправки, и «сначала пишу, потом читаю» встало бы намертво, как только
// написанное перестало помещаться в окно.
func ExchangeUsage(rw io.ReadWriter, l *ledger.Ledger) error {
	type half struct{ err error }

	reading := make(chan half, 1)
	writing := make(chan half, 1)

	go func() {
		frame, err := ReadFrame(rw)
		if err != nil {
			reading <- half{err: err}
			return
		}
		if frame.Kind != KindUsage {
			reading <- half{err: fmt.Errorf("control: ждали %s, пришёл %s", KindUsage, frame.Kind)}
			return
		}
		var snap ledger.Snapshot
		if err := json.Unmarshal(frame.Payload, &snap); err != nil {
			reading <- half{err: fmt.Errorf("control: разбор расхода: %w", err)}
			return
		}
		l.Merge(snap)
		reading <- half{}
	}()

	go func() {
		body, err := json.Marshal(l.Snapshot())
		if err != nil {
			writing <- half{err: fmt.Errorf("control: сборка расхода: %w", err)}
			return
		}
		writing <- half{err: WriteFrame(rw, KindUsage, body)}
	}()

	r, w := <-reading, <-writing
	if r.err != nil {
		return r.err
	}
	return w.err
}
