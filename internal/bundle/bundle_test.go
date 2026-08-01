package bundle

import (
	"errors"
	"strings"
	"testing"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func sample(t *testing.T) *Bundle {
	t.Helper()
	fp, err := oplog.ParseFingerprint(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("отпечаток: %v", err)
	}
	return &Bundle{
		Version:   Version,
		Network:   "qdiver",
		Genesis:   fp,
		ClientID:  "vasya",
		ClientKey: []byte("ключ-клиента-которого-хватит-на-подпись"),
		Ingress: []Node{
			{
				ID:        "qdiver1",
				Domain:    "qdiver1.example.com",
				Endpoints: []string{"192.0.2.1:443", "[2001:db8::1]:443"},
				PublicKey: oplog.PublicKey("ключ-узла"),
			},
		},
		HasEgress: true,
		Settings:  oplog.Settings{BrutalUpMbps: 20, BrutalDownMbps: 100},
	}
}

func TestBundleSurvivesRoundTrip(t *testing.T) {
	want := sample(t)

	uri, err := Encode(want, "")
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	if !strings.HasPrefix(uri, Scheme) {
		t.Fatalf("ссылка без схемы: %s", uri)
	}

	got, err := Decode(uri, "")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got.ClientID != want.ClientID || string(got.ClientKey) != string(want.ClientKey) {
		t.Fatalf("клиент разъехался: %+v", got)
	}
	if got.Genesis != want.Genesis {
		t.Fatalf("отпечаток разъехался: %s против %s", got.Genesis, want.Genesis)
	}
	if len(got.Ingress) != 1 || got.Ingress[0].Domain != want.Ingress[0].Domain {
		t.Fatalf("узлы разъехались: %+v", got.Ingress)
	}
	if len(got.Ingress[0].Endpoints) != 2 {
		t.Fatalf("адреса потерялись: %+v", got.Ingress[0].Endpoints)
	}
	if !got.HasEgress || got.Settings.BrutalDownMbps != 100 {
		t.Fatalf("параметры разъехались: %+v", got)
	}
}

// Отпечаток в бандле человек сверяет глазами, значит он обязан быть строкой, а не массивом
// из тридцати двух чисел.
func TestFingerprintIsWrittenAsHex(t *testing.T) {
	raw, err := sample(t).Genesis.MarshalJSON()
	if err != nil {
		t.Fatalf("отпечаток: %v", err)
	}
	if string(raw) != `"`+strings.Repeat("ab", 32)+`"` {
		t.Fatalf("отпечаток записан как %s", raw)
	}
}

func TestPasswordProtectsTheBundle(t *testing.T) {
	want := sample(t)

	uri, err := Encode(want, "тайное слово")
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	// Открытым текстом в ссылке не должно остаться ничего узнаваемого.
	if strings.Contains(uri, "vasya") || strings.Contains(uri, "qdiver1") {
		t.Fatalf("зашифрованная ссылка выдаёт содержимое: %s", uri)
	}

	if _, err := Decode(uri, ""); !errors.Is(err, ErrNeedPassword) {
		t.Fatalf("без пароля ждали ErrNeedPassword, получили %v", err)
	}
	if _, err := Decode(uri, "не то слово"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("с чужим паролем ждали ErrWrongPassword, получили %v", err)
	}

	got, err := Decode(uri, "тайное слово")
	if err != nil {
		t.Fatalf("разбор с паролем: %v", err)
	}
	if got.ClientID != want.ClientID {
		t.Fatalf("клиент разъехался: %+v", got)
	}
}

// Пароль к незашифрованному бандлу — не мелочь: человек думает, что ссылка защищена, а она
// открыта. Молчать об этом нельзя.
func TestPasswordOnPlainBundleIsAnError(t *testing.T) {
	uri, err := Encode(sample(t), "")
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	if _, err := Decode(uri, "какой-то пароль"); !errors.Is(err, ErrUnexpectedPass) {
		t.Fatalf("ждали ErrUnexpectedPass, получили %v", err)
	}
}

func TestDecodeRejectsRubbish(t *testing.T) {
	cases := map[string]string{
		"пустая строка":     "",
		"чужая схема":       "https://example.com/",
		"не base64":         Scheme + "не-ба-зэ-64!!!",
		"пустое тело":       Scheme + "",
		"неизвестный вид":   Scheme + "_wAAAA",
		"обрезанный gzip":   Scheme + "AB8L",
		"схема без данных":  "qdiver://",
		"мусор после схемы": Scheme + "AAAAAAAAAAAAAAAA",
	}
	for name, uri := range cases {
		if b, err := Decode(uri, ""); err == nil {
			t.Fatalf("%s: принят как бандл: %+v", name, b)
		}
	}
}

func TestBundleWithoutIngressIsRefused(t *testing.T) {
	b := sample(t)
	b.Ingress = nil
	if _, err := Encode(b, ""); !errors.Is(err, ErrNoIngress) {
		t.Fatalf("ждали ErrNoIngress, получили %v", err)
	}
}
