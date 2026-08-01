package decoy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, s *Site, method, path string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Result()
}

func TestRootServesStub(t *testing.T) {
	s := New()
	resp := get(t, s, http.MethodGet, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код ответа: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("тип содержимого: %q", ct)
	}
}

// Ответ не должен нести ничего, чего не бывает у файла, отданного веб-сервером.
func TestNoRevealingHeaders(t *testing.T) {
	s := New()
	for _, path := range []string{"/", "/нет-такой-страницы"} {
		resp := get(t, s, http.MethodGet, path)
		for name := range resp.Header {
			switch {
			case strings.HasPrefix(strings.ToLower(name), "x-"):
				t.Fatalf("%s: заголовок %s выдаёт программу", path, name)
			case strings.EqualFold(name, "Server"):
				t.Fatalf("%s: заголовок Server выдаёт программу", path)
			}
		}
	}
}

// Тело ответа не должно содержать ни имени проекта, ни намёка на него.
func TestBodyDoesNotMentionTheProject(t *testing.T) {
	s := New()
	for _, path := range []string{"/", "/нет-такой-страницы"} {
		resp := get(t, s, http.MethodGet, path)
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		body := strings.ToLower(string(buf[:n]))
		for _, word := range []string{"qdiver", "quic-diver", "quic diver", "golang", "go1."} {
			if strings.Contains(body, word) {
				t.Fatalf("%s: тело содержит %q", path, word)
			}
		}
	}
}

func TestUnknownPathIsPlainNotFound(t *testing.T) {
	s := New()
	resp := get(t, s, http.MethodGet, "/api/v1/whatever")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("код ответа: %d", resp.StatusCode)
	}
}

// Страницы ошибок однородны: одна и та же вёрстка на всех узлах и на все коды.
func TestErrorPagesShareShape(t *testing.T) {
	s := New()
	rec404 := httptest.NewRecorder()
	s.Error(rec404, httptest.NewRequest(http.MethodGet, "/x", nil), http.StatusNotFound)
	rec503 := httptest.NewRecorder()
	s.Error(rec503, httptest.NewRequest(http.MethodGet, "/x", nil), http.StatusServiceUnavailable)

	if rec404.Code != 404 || rec503.Code != 503 {
		t.Fatalf("коды: %d и %d", rec404.Code, rec503.Code)
	}
	shape := func(body string) string {
		// Отбрасываем строки с самим текстом ошибки, сравниваем каркас.
		var out []string
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "<h1>") || strings.HasPrefix(line, "<p>") || strings.HasPrefix(line, "<title>") {
				continue
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}
	if shape(rec404.Body.String()) != shape(rec503.Body.String()) {
		t.Fatal("страницы ошибок различаются каркасом, а не только текстом")
	}
}

func TestHeadHasNoBody(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/", nil))
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD вернул тело длиной %d", rec.Body.Len())
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD должен сообщать длину, как это делает статика")
	}
}

func TestPostIsRejectedLikeStatic(t *testing.T) {
	s := New()
	resp := get(t, s, http.MethodPost, "/")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("код ответа: %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
		t.Fatalf("Allow: %q", allow)
	}
}

// Дата последнего изменения у статической страницы не прыгает от запроса к запросу.
func TestLastModifiedIsStable(t *testing.T) {
	s := New()
	first := get(t, s, http.MethodGet, "/").Header.Get("Last-Modified")
	time.Sleep(2 * time.Millisecond)
	second := get(t, s, http.MethodGet, "/").Header.Get("Last-Modified")
	if first == "" {
		t.Fatal("Last-Modified не отдан")
	}
	if first != second {
		t.Fatalf("дата изменения прыгает: %q против %q", first, second)
	}
}

func TestProbeDetectionIsAdvisoryOnly(t *testing.T) {
	if !IsProbe(httptest.NewRequest(http.MethodGet, "/.env", nil)) {
		t.Fatal("запрос /.env не опознан как прощупывание")
	}
	if IsProbe(httptest.NewRequest(http.MethodGet, "/about", nil)) {
		t.Fatal("обычный путь принят за прощупывание")
	}

	// И главное: реакция на прощупывание не отличается от реакции на любой другой путь.
	s := New()
	probe := get(t, s, http.MethodGet, "/.env")
	normal := get(t, s, http.MethodGet, "/about")
	if probe.StatusCode != normal.StatusCode {
		t.Fatalf("прощупывание получает иной ответ: %d против %d", probe.StatusCode, normal.StatusCode)
	}
}
