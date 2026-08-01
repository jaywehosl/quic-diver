// Package decoy — то, что видит любой, кто пришёл на узел без приветствия.
//
// Это не маскировка и не обман: узел действительно отдаёт обычный сайт по обычному HTTP,
// с настоящим сертификатом и без единого нестандартного заголовка. Сайт-заглушка на домене,
// который пока ни для чего не используется, — вещь совершенно обыденная.
//
// # Чего здесь нельзя делать
//
// Узел не должен отвечать посторонним иначе, чем ответил бы такой сайт. Отсюда три правила,
// которые легко нарушить по невнимательности:
//
//   - неудачное приветствие обязано выглядеть как обычный 404, а не как отдельная ошибка.
//     Иначе подбором пути можно выяснить, что узел — не просто сайт;
//   - страницы ошибок не должны выдавать ни версию, ни имя программы;
//   - ответ не должен нести заголовков, которых не бывает у статики.
package decoy

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Site отдаёт заглушку и однородные страницы ошибок.
type Site struct {
	// Title — заголовок страницы. Пустой означает значение по умолчанию.
	Title string
	// Body — содержимое заглушки. Пустое означает страницу по умолчанию.
	Body string
	// Modified — время последнего изменения, попадает в Last-Modified. Нулевое означает
	// время запуска узла: у статической страницы эта дата не должна прыгать от запроса
	// к запросу.
	Modified time.Time
}

// New собирает сайт со значениями по умолчанию.
func New() *Site {
	return &Site{Modified: time.Now().UTC().Truncate(time.Hour)}
}

const defaultTitle = "Under construction"

const defaultBody = `<h1>Under construction</h1>
<p>This site is not ready yet. Please check back later.</p>`

// page собирает страницу целиком.
func (s *Site) page(title, body string) string {
	if title == "" {
		title = defaultTitle
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body { font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 34rem; padding: 0 1rem;
       color: #222; line-height: 1.5; }
h1 { font-weight: 500; font-size: 1.6rem; }
p { color: #555; }
</style>
%s
</html>
`, title, body)
}

// ServeHTTP отдаёт заглушку на корень и одинаковую страницу «не найдено» на всё остальное.
func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		// Статический сайт не умеет ничего, кроме чтения, — и отвечает именно так.
		w.Header().Set("Allow", "GET, HEAD")
		s.Error(w, r, http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/" {
		s.Error(w, r, http.StatusNotFound)
		return
	}

	title, body := s.Title, s.Body
	if body == "" {
		body = defaultBody
	}
	s.write(w, r, http.StatusOK, s.page(title, body))
}

// Error отдаёт однородную страницу ошибки.
//
// Через неё же уходит всякий, кого не пустили дальше приветствия: снаружи это неотличимо от
// запроса несуществующей страницы, каковым для стороннего наблюдателя и является.
func (s *Site) Error(w http.ResponseWriter, r *http.Request, code int) {
	title := fmt.Sprintf("%d %s", code, http.StatusText(code))
	body := fmt.Sprintf("<h1>%s</h1>\n<p>%s</p>", title, errorText(code))
	s.write(w, r, code, s.page(title, body))
}

func errorText(code int) string {
	switch code {
	case http.StatusNotFound:
		return "The requested page was not found on this server."
	case http.StatusMethodNotAllowed:
		return "That method is not allowed for this resource."
	case http.StatusServiceUnavailable:
		return "The server is temporarily unable to handle the request."
	case http.StatusRequestTimeout:
		return "The server timed out waiting for the request."
	default:
		return "The server could not complete the request."
	}
}

func (s *Site) write(w http.ResponseWriter, r *http.Request, code int, page string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", fmt.Sprint(len(page)))
	if !s.Modified.IsZero() {
		h.Set("Last-Modified", s.Modified.UTC().Format(http.TimeFormat))
	}
	// Ни Server, ни X-*: всё, чего не бывает у отданного веб-сервером файла, — примета.
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(page))
}

// Handler возвращает обработчик, годный и для HTTP/1.1 с HTTP/2, и для HTTP/3.
func (s *Site) Handler() http.Handler { return s }

// IsProbe сообщает, похож ли запрос на автоматическое прощупывание.
//
// Нужен только для журнала узла: реагировать на такие запросы иначе, чем на любые другие,
// нельзя — именно разница в реакции и выдаёт.
func IsProbe(r *http.Request) bool {
	p := strings.ToLower(r.URL.Path)
	for _, s := range []string{"/.env", "/.git", "/wp-", "/admin", "/phpmyadmin", "/.well-known/acme"} {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}
