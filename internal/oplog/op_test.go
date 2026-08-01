package oplog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"
)

func mustSigner(t *testing.T) *MemorySigner {
	t.Helper()
	s, err := GenerateSigner()
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	return s
}

func signedOp(t *testing.T, s Signer, kind Kind, counter uint64, payload string) *Op {
	t.Helper()
	op := &Op{
		Kind:    kind,
		Counter: counter,
		Time:    time.Now(),
		Payload: []byte(payload),
	}
	if err := op.Sign(s); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	return op
}

func TestRoundTrip(t *testing.T) {
	s := mustSigner(t)
	op := signedOp(t, s, KindClientAdd, 1, `{"id":"вася"}`)

	var buf bytes.Buffer
	if err := op.Encode(&buf); err != nil {
		t.Fatalf("кодирование: %v", err)
	}

	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got.Kind != op.Kind || got.Counter != op.Counter || got.Key != op.Key {
		t.Fatalf("заголовок разъехался: %+v против %+v", got, op)
	}
	if !bytes.Equal(got.Payload, op.Payload) {
		t.Fatalf("тело разъехалось: %q против %q", got.Payload, op.Payload)
	}
	if !got.Time.Equal(op.Time) {
		t.Fatalf("время разъехалось: %v против %v", got.Time, op.Time)
	}
	if err := got.Verify(s.Public()); err != nil {
		t.Fatalf("подпись разобранной записи не сошлась: %v", err)
	}
}

// Время под подписью хранится с точностью до миллисекунды. Если Sign не усечёт его в самой
// структуре, подпись сойдётся у разобранной записи, но не у той, что осталась в памяти.
func TestSignTruncatesTimeSoVerifyMatchesInMemory(t *testing.T) {
	s := mustSigner(t)
	op := &Op{
		Kind:    KindClientAdd,
		Counter: 1,
		Time:    time.Date(2026, 7, 30, 12, 0, 0, 123456789, time.UTC),
		Payload: []byte(`{}`),
	}
	if err := op.Sign(s); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if err := op.Verify(s.Public()); err != nil {
		t.Fatalf("подпись не сходится на той же структуре: %v", err)
	}
	if op.Time.Nanosecond()%int(time.Millisecond) != 0 {
		t.Fatalf("время не усечено до миллисекунд: %v", op.Time)
	}
}

func TestVerifyRejectsForeignKey(t *testing.T) {
	s := mustSigner(t)
	other := mustSigner(t)
	op := signedOp(t, s, KindClientAdd, 1, `{}`)

	if err := op.Verify(other.Public()); err == nil {
		t.Fatal("чужой ключ принят")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	s := mustSigner(t)
	op := signedOp(t, s, KindClientAdd, 1, `{"limit":1}`)
	op.Payload = []byte(`{"limit":9}`)

	if err := op.Verify(s.Public()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("подменённое тело принято: %v", err)
	}
}

func TestVerifyRejectsTamperedHeader(t *testing.T) {
	s := mustSigner(t)
	for name, mutate := range map[string]func(*Op){
		"вид":     func(o *Op) { o.Kind = KindNodeRevoke },
		"счётчик": func(o *Op) { o.Counter = 42 },
		"время":   func(o *Op) { o.Time = o.Time.Add(time.Second) },
		"подпись": func(o *Op) { o.Sig[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			op := signedOp(t, s, KindClientAdd, 1, `{}`)
			mutate(op)
			if err := op.Verify(s.Public()); err == nil {
				t.Fatal("изменённая запись принята")
			}
		})
	}
}

// Подпись журнала не должна годиться нигде, кроме журнала: разделение контекстом.
func TestSignatureIsBoundToContext(t *testing.T) {
	s := mustSigner(t)
	op := signedOp(t, s, KindClientAdd, 1, `{}`)

	raw := op.signedBytes()
	withoutContext := raw[len(signContext):]
	if ed25519.Verify(s.Public(), withoutContext, op.Sig) {
		t.Fatal("подпись сходится без контекста — разделения нет")
	}
}

func TestSignRejectsZeroCounter(t *testing.T) {
	s := mustSigner(t)
	op := &Op{Kind: KindClientAdd, Counter: 0, Time: time.Now()}
	if err := op.Sign(s); !errors.Is(err, ErrCounterIsZero) {
		t.Fatalf("нулевой счётчик принят: %v", err)
	}
}

func TestSignRejectsOversizedPayload(t *testing.T) {
	s := mustSigner(t)
	op := &Op{
		Kind:    KindClientAdd,
		Counter: 1,
		Time:    time.Now(),
		Payload: make([]byte, MaxPayloadSize+1),
	}
	if err := op.Sign(s); !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("огромное тело принято: %v", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode(bytes.NewReader([]byte("ХЗЧТОЭТОТАКОЕ__________________________"))); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("мусор принят за запись: %v", err)
	}
}

func TestDecodeRejectsTruncated(t *testing.T) {
	s := mustSigner(t)
	op := signedOp(t, s, KindClientAdd, 1, `{"id":"вася"}`)
	full, err := op.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	for _, cut := range []int{headerSize + 1, len(full) - 1} {
		_, err := Decode(bytes.NewReader(full[:cut]))
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("обрыв на %d байтах не пойман: %v", cut, err)
		}
	}
	// Пустой поток — не обрыв, а его законный конец.
	if _, err := Decode(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("конец потока должен давать io.EOF, получено: %v", err)
	}
}

// Тело записи, которую эта версия не понимает, обязано доезжать в целости: узел старой
// версии хранит и пересылает такие записи, не применяя их.
func TestUnknownKindSurvivesRoundTrip(t *testing.T) {
	s := mustSigner(t)
	op := signedOp(t, s, Kind(60000), 1, `{"из":"будущего"}`)

	var buf bytes.Buffer
	if err := op.Encode(&buf); err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got.Kind.Known() {
		t.Fatal("вид из будущего считается известным")
	}
	if err := got.Verify(s.Public()); err != nil {
		t.Fatalf("подпись неизвестной записи должна проверяться: %v", err)
	}
	if got.Kind.RequiredScope() != ScopeOwner {
		t.Fatal("неизвестной операции нужны права владельца, иначе её протащит оператор")
	}
}

func TestBytesMatchesEncode(t *testing.T) {
	s := mustSigner(t)
	op := signedOp(t, s, KindNodeAdd, 7, `{"узел":"варшава"}`)

	var buf bytes.Buffer
	if err := op.Encode(&buf); err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	raw, err := op.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), raw) {
		t.Fatal("Encode и Bytes дают разное")
	}
}

func TestStreamOfOps(t *testing.T) {
	s := mustSigner(t)
	var buf bytes.Buffer
	const n = 5
	for i := uint64(1); i <= n; i++ {
		op := signedOp(t, s, KindClientAdd, i, `{}`)
		if err := op.Encode(&buf); err != nil {
			t.Fatalf("кодирование %d: %v", i, err)
		}
	}

	for i := uint64(1); i <= n; i++ {
		got, err := Decode(&buf)
		if err != nil {
			t.Fatalf("разбор %d: %v", i, err)
		}
		if got.Counter != i {
			t.Fatalf("порядок нарушен: ждали %d, получили %d", i, got.Counter)
		}
	}
	if _, err := Decode(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("после последней записи ждали io.EOF, получили %v", err)
	}
}

func TestKeyIDRoundTrip(t *testing.T) {
	s := mustSigner(t)
	id := s.KeyID()
	parsed, err := ParseKeyID(id.String())
	if err != nil {
		t.Fatalf("разбор идентификатора: %v", err)
	}
	if parsed != id {
		t.Fatalf("идентификатор разъехался: %s против %s", parsed, id)
	}
	if id.IsZero() {
		t.Fatal("идентификатор не должен быть нулевым")
	}
}

func TestScopeParsing(t *testing.T) {
	for _, s := range []Scope{ScopeViewer, ScopeOperator, ScopeOwner} {
		got, err := ParseScope(s.String())
		if err != nil {
			t.Fatalf("разбор %s: %v", s, err)
		}
		if got != s {
			t.Fatalf("область прав разъехалась: %s против %s", got, s)
		}
		if !s.Valid() {
			t.Fatalf("%s должна быть допустимой", s)
		}
	}
	if Scope(200).Valid() {
		t.Fatal("неизвестная область прав не должна считаться допустимой")
	}
	if _, err := ParseScope("админ"); err == nil {
		t.Fatal("неизвестное имя области прав принято")
	}
}
