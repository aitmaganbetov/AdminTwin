package telemetry

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Day — сутки (для сроков ретенции и окон вида "7d").
const Day = 24 * time.Hour

var windowRe = regexp.MustCompile(`^([1-9][0-9]{0,3})([smhd])$`)

// ParseWindow разбирает окно вида 30s, 15m, 1h, 7d (формат контрактов read tools).
func ParseWindow(s string) (time.Duration, error) {
	m := windowRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid window %q (expected e.g. 15m, 1h, 7d)", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": Day}[m[2]]
	return time.Duration(n) * unit, nil
}

var sevRank = map[Severity]int{SevInfo: 1, SevLow: 2, SevMedium: 3, SevHigh: 4, SevCritical: 5}

// Rank — числовой ранг severity (0 — неизвестная).
func (s Severity) Rank() int { return sevRank[s] }

// Valid — известная ли severity.
func (s Severity) Valid() bool { return sevRank[s] > 0 }

// AtLeast — s не ниже min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// NewID — UUID v4.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID — строка в формате UUID (требование output_schema read tools).
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// Truncate обрезает строку до n байт, не разрывая UTF-8, и заменяет управляющие символы
// (кроме табуляции) пробелами. Используется для недоверенных строк (заголовки событий, строки журналов).
func Truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r != '\t' && unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func copyLabels(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
