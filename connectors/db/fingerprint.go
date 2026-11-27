package db

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Fingerprint нормализует текст SQL-запроса: строковые литералы ('...', E'...', $tag$...$tag$),
// числа и комментарии заменяются на «?» / удаляются, пробелы схлопываются, списки «?, ?, ?» сворачиваются.
// Литералы не возвращаются никогда — даже из оборванного (усечённого track_activity_query_size) запроса:
// незакрытая строка или комментарий поглощают остаток. Результат ограничен limit байтами.
func Fingerprint(q string, limit int) string {
	var b strings.Builder
	n := len(q)
	space := false
	emit := func(s string) {
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteString(s)
	}
	prevIdent := func() byte {
		s := b.String()
		if len(s) == 0 || space {
			return 0
		}
		return s[len(s)-1]
	}
	for i := 0; i < n; {
		c := q[i]
		switch {
		case c == '-' && i+1 < n && q[i+1] == '-':
			for i < n && q[i] != '\n' {
				i++
			}
			space = true
		case c == '/' && i+1 < n && q[i+1] == '*':
			depth := 0
			for i < n {
				if i+1 < n && q[i] == '/' && q[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if i+1 < n && q[i] == '*' && q[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
			space = true
		case c == '\'':
			// E'..' допускает экранирование обратной косой чертой; префикс уже выведен как идентификатор.
			backslash := false
			if p := prevIdent(); p == 'E' || p == 'e' {
				backslash = true
			}
			i++
			for i < n {
				if backslash && q[i] == '\\' {
					i += 2
					continue
				}
				if q[i] == '\'' {
					if i+1 < n && q[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			trimLiteralPrefix(&b)
			emit("?")
		case c == '$' && i+1 < n && (q[i+1] == '$' || isIdentStart(q[i+1])):
			end := strings.IndexByte(q[i+1:], '$')
			tag := ""
			if end >= 0 {
				tag = q[i : i+end+2]
			}
			if end < 0 || !dollarTagRe.MatchString(tag) {
				emit("$")
				i++
				continue
			}
			body := q[i+len(tag):]
			if j := strings.Index(body, tag); j >= 0 {
				i += len(tag) + j + len(tag)
			} else {
				i = n
			}
			emit("?")
		case c == '"':
			j := i + 1
			for j < n {
				if q[j] == '"' {
					if j+1 < n && q[j+1] == '"' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			emit(q[i:min(j, n)])
			i = j
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(q[i+1])):
			if p := prevIdent(); p != 0 && isIdentChar(p) {
				emit(string(c)) // часть идентификатора (t1, col2)
				i++
				continue
			}
			// Числа, в т.ч. 1.5e-3, 0x1F, 1_000: поглощаем символы идентификатора, точку и знак экспоненты.
			for i < n && (isIdentChar(q[i]) || q[i] == '.' ||
				((q[i] == '+' || q[i] == '-') && (q[i-1] == 'e' || q[i-1] == 'E'))) {
				i++
			}
			emit("?")
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
			space = true
			i++
		default:
			if c < 0x20 || c == 0x7f {
				i++
				continue
			}
			emit(string(c))
			i++
		}
	}
	out := listRe.ReplaceAllString(b.String(), "?, ...")
	if len(out) > limit {
		cut := limit - 3
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:max(cut, 0)] + "..."
	}
	return strings.ToValidUTF8(out, "?")
}

var (
	dollarTagRe = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)?\$$`)
	listRe      = regexp.MustCompile(`\?(\s*,\s*\?)+`)
)

// trimLiteralPrefix удаляет префикс литерала (E, B, X, U&, N), выведенный как идентификатор.
func trimLiteralPrefix(b *strings.Builder) {
	s := b.String()
	for _, p := range []string{"U&", "u&", "E", "e", "B", "b", "X", "x", "N", "n"} {
		if strings.HasSuffix(s, p) {
			rest := s[:len(s)-len(p)]
			if rest == "" || !isIdentChar(rest[len(rest)-1]) {
				b.Reset()
				b.WriteString(rest)
				return
			}
		}
	}
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isIdentStart(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') || c >= 0x80 }
func isIdentChar(c byte) bool  { return isIdentStart(c) || isDigit(c) || c == '$' }
