package linux

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrUnsafeArgument — аргумент содержит NUL, перевод строки или иной управляющий символ, либо невалидный UTF-8.
// Такие аргументы не экранируются, а отклоняются: SSH exec передаёт строку, которую интерпретирует
// login shell удалённой стороны.
var ErrUnsafeArgument = errors.New("argument contains forbidden characters")

// isSafe — символы, которые POSIX shell не интерпретирует; такие аргументы передаются без кавычек.
func isSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("@%+=:,./_-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// Quote экранирует один аргумент для POSIX shell: безопасные строки — как есть, остальные — в одинарных
// кавычках, где «'» заменяется на '"'"'. Внутри одинарных кавычек shell не выполняет подстановок
// ($, `, \, *, ?, ~ и т.д. — литералы).
func Quote(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", ErrUnsafeArgument
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029' || (r >= 0x80 && r < 0xa0) {
			return "", ErrUnsafeArgument
		}
	}
	if s == "" {
		return "''", nil
	}
	if isSafe(s) {
		return s, nil
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'", nil
}

// Join экранирует каждый элемент argv отдельно и соединяет пробелами.
func Join(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("empty argv")
	}
	parts := make([]string, len(argv))
	for i, a := range argv {
		q, err := Quote(a)
		if err != nil {
			return "", err
		}
		parts[i] = q
	}
	return strings.Join(parts, " "), nil
}
