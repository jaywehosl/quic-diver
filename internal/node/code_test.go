package node

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func testPub(t *testing.T) oplog.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	return oplog.PublicKey(pub)
}

// Код считается из ключа: один и тот же узел всегда называет одно и то же.
func TestCodeIsStableAndShort(t *testing.T) {
	pub := testPub(t)

	code := Code(pub)
	if code != Code(pub) {
		t.Fatal("код меняется от вызова к вызову")
	}
	if got := len(NormalizeCode(code)); got != CodeLength {
		t.Fatalf("в коде %d знаков, ожидалось %d: %q", got, CodeLength, code)
	}
	if !strings.Contains(code, "-") {
		t.Fatalf("код без разделителя, читать тяжело: %q", code)
	}
	// Знаки, которые путают с единицей и нулём, в коде появиться не должны: его переносят
	// руками с экрана на экран.
	for _, bad := range []string{"I", "L", "O", "U"} {
		if strings.Contains(code, bad) {
			t.Fatalf("в коде есть %s: %q", bad, code)
		}
	}
}

// Разные узлы — разные коды.
func TestDifferentKeysDifferentCodes(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		code := Code(testPub(t))
		if _, dup := seen[code]; dup {
			t.Fatalf("два ключа дали один код: %s", code)
		}
		seen[code] = struct{}{}
	}
}

// Человек введёт код как придётся: строчными, без дефиса, с пробелом.
func TestCodeMatchesForgivesTyping(t *testing.T) {
	pub := testPub(t)
	code := Code(pub)
	bare := NormalizeCode(code)

	for _, entered := range []string{
		code,
		bare,
		strings.ToLower(code),
		" " + strings.ToLower(bare[:4]) + " " + bare[4:] + " ",
		bare[:4] + "--" + bare[4:],
	} {
		if !CodeMatches(pub, entered) {
			t.Fatalf("код %q не принят, а должен: настоящий %q", entered, code)
		}
	}
}

// Чужой код не проходит — ради этого всё и делалось.
func TestWrongCodeRejected(t *testing.T) {
	mine, theirs := testPub(t), testPub(t)

	if CodeMatches(mine, Code(theirs)) {
		t.Fatal("код чужого узла принят за свой")
	}
	if CodeMatches(mine, "") {
		t.Fatal("пустой код принят")
	}
	// Один неверный знак: ровно то, чем опечатка отличается от подделки, — и то и другое
	// обязано быть отвергнуто.
	bare := []byte(NormalizeCode(Code(mine)))
	if bare[0] == '0' {
		bare[0] = '1'
	} else {
		bare[0] = '0'
	}
	if CodeMatches(mine, string(bare)) {
		t.Fatal("код с опечаткой принят")
	}
}
