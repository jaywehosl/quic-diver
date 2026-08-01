// Package geodata читает базы geosite и geoip в формате v2fly.
//
// Формат — обычный protobuf, схема лежит в v2fly как
// `app/router/routercommon/common.proto`. Нам из неё нужны четыре сообщения:
//
//	message Domain     { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//	message GeoSite    { string country_code = 1; repeated Domain domain = 2; }
//	message CIDR       { bytes ip = 1; uint32 prefix = 2; }
//	message GeoIP      { string country_code = 1; repeated CIDR cidr = 2; }
//
// Разбираем сами, без генерации кода и без runtime-зависимости. Причина простая: нужных
// сообщений четыре, wire-формат protobuf занимает полторы сотни строк, а тянуть ради этого
// google.golang.org/protobuf в клиент, который поедет на телефон, — несоразмерно.
package geodata

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Типы полей protobuf, которые встречаются в этих схемах.
const (
	wireVarint = 0
	wireBytes  = 2
)

var (
	ErrTruncated = errors.New("geodata: данные обрываются")
	ErrWireType  = errors.New("geodata: неожиданный вид поля")
)

// reader читает protobuf-сообщение.
//
// Всё, что он получает, приходит из файла, скачанного по сети. Поэтому каждая длина
// проверяется против остатка буфера: заявленный размер поля не повод выделять память.
type reader struct {
	buf []byte
	pos int
}

func newReader(b []byte) *reader { return &reader{buf: b} }

func (r *reader) done() bool { return r.pos >= len(r.buf) }

// tag читает номер поля и его вид.
func (r *reader) tag() (field int, wire int, err error) {
	v, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	return int(v >> 3), int(v & 7), nil
}

func (r *reader) varint() (uint64, error) {
	v, n := binary.Uvarint(r.buf[r.pos:])
	if n <= 0 {
		return 0, ErrTruncated
	}
	r.pos += n
	return v, nil
}

// bytes читает поле переменной длины.
//
// Возвращается срез исходного буфера, а не копия: базы весят мегабайты, и копировать каждую
// строку значило бы удвоить расход памяти на ровном месте. Буфер после разбора живёт столько
// же, сколько сами списки.
func (r *reader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.buf)-r.pos) {
		return nil, fmt.Errorf("%w: заявлено %d байт, осталось %d", ErrTruncated, n, len(r.buf)-r.pos)
	}
	start := r.pos
	r.pos += int(n)
	return r.buf[start:r.pos], nil
}

// skip пропускает поле, которого мы не понимаем.
//
// Пропускать, а не падать: базы обновляются чаще нашего клиента, и новое поле в них не повод
// отказаться работать со списками, которые мы прекрасно понимаем.
func (r *reader) skip(wire int) error {
	switch wire {
	case wireVarint:
		_, err := r.varint()
		return err
	case wireBytes:
		_, err := r.bytes()
		return err
	case 5: // fixed32
		if len(r.buf)-r.pos < 4 {
			return ErrTruncated
		}
		r.pos += 4
		return nil
	case 1: // fixed64
		if len(r.buf)-r.pos < 8 {
			return ErrTruncated
		}
		r.pos += 8
		return nil
	default:
		return fmt.Errorf("%w: %d", ErrWireType, wire)
	}
}
