//go:build unix

package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxToolArgumentsBytes = 65536   // 64 KiB
	MaxConfigFileBytes    = 4194304 // 4 MiB
	MaxJSONDepth          = 16
	MaxSafeInt53          = (int64(1) << 53) - 1
	MinSafeInt53          = -((int64(1) << 53) - 1)
)

// asciiLower converts ASCII uppercase 'A'-'Z' to 'a'-'z' without Unicode case-folding
// (avoiding Kelvin sign U+212A or Turkish dotless-i collisions).
func asciiLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func asciiUpper(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ValidateSafeJSONString enforces Control 5 string character hygiene:
// rejects control chars (except \t, \n, \r), DEL and C1 controls (0x7F..0x9F),
// Unicode bidi overrides/isolates, and replacement char U+FFFD (including unpaired surrogates).
func ValidateSafeJSONString(s string) error {
	if !utf8.ValidString(s) {
		return NewError(ErrInvalidControlChar, 1, "string contains invalid UTF-8 bytes")
	}
	for _, r := range s {
		if r == utf8.RuneError {
			return NewError(ErrInvalidControlChar, 1, "string contains U+FFFD replacement character or unpaired surrogate")
		}
		if r <= 0x1F && r != 0x09 && r != 0x0A && r != 0x0D {
			return NewError(ErrInvalidControlChar, 1, "string contains disallowed C0 control character U+%04X", r)
		}
		if r >= 0x7F && r <= 0x9F {
			return NewError(ErrInvalidControlChar, 1, "string contains DEL or C1 control character U+%04X", r)
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C {
			return NewError(ErrInvalidControlChar, 1, "string contains Unicode bidirectional control character U+%04X", r)
		}
	}
	return nil
}

// SanitizeSafeJSONString replaces any invalid UTF-8 byte, U+FFFD replacement character,
// disallowed C0/C1 control character, or Unicode bidirectional override/isolate rune
// with a printable ASCII escape sequence (\xXX or \uXXXX) so that untrusted strings
// recorded in audit.jsonl or state.db can never poison subsequent strict JSON decoding.
func SanitizeSafeJSONString(s string) string {
	if ValidateSafeJSONString(s) == nil {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError {
			if width == 1 {
				fmt.Fprintf(&b, `\x%02x`, s[i])
			} else {
				b.WriteString(`\ufffd`)
			}
			i += width
			continue
		}
		if (r <= 0x1F && r != 0x09 && r != 0x0A && r != 0x0D) ||
			(r >= 0x7F && r <= 0x9F) ||
			(r >= 0x202A && r <= 0x202E) ||
			(r >= 0x2066 && r <= 0x2069) ||
			r == 0x200E || r == 0x200F || r == 0x061C {
			fmt.Fprintf(&b, `\u%04x`, r)
			i += width
			continue
		}
		b.WriteRune(r)
		i += width
	}
	return b.String()
}

// SanitizeSafeJSONValue recursively sanitizes all strings and object keys in a JSON value tree.
func SanitizeSafeJSONValue(v any) any {
	switch x := v.(type) {
	case string:
		return SanitizeSafeJSONString(x)
	case []string:
		out := make([]string, len(x))
		for i, elem := range x {
			out[i] = SanitizeSafeJSONString(elem)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, elem := range x {
			out[i] = SanitizeSafeJSONValue(elem)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[SanitizeSafeJSONString(k)] = SanitizeSafeJSONValue(val)
		}
		return out
	default:
		return v
	}
}

// DecodeStrictJSON parses raw JSON with the 64 KiB cap, max depth 16, exact duplicate key rejection,
// optional ASCII case-colliding key rejection, IEEE-754 int53 precision bounds, and control/bidi rejection.
func DecodeStrictJSON(raw []byte, rejectCaseCollision bool) (any, error) {
	return DecodeStrictJSONWithCap(raw, MaxToolArgumentsBytes, rejectCaseCollision)
}

// DecodeStrictJSONObject decodes raw JSON and requires the top-level value to be a JSON object.
// An empty slice is treated as an empty JSON object `{}`.
func DecodeStrictJSONObject(raw []byte, rejectCaseCollision bool) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	val, err := DecodeStrictJSON(raw, rejectCaseCollision)
	if err != nil {
		return nil, err
	}
	obj, ok := val.(map[string]any)
	if !ok {
		return nil, NewError(ErrSchemaValidationFailed, 1, "top-level JSON value must be an object")
	}
	return obj, nil
}

// DecodeStrictJSONWithCap parses raw JSON with a caller-specified byte cap.
func DecodeStrictJSONWithCap(raw []byte, maxBytes int, rejectCaseCollision bool) (any, error) {
	if len(raw) > maxBytes {
		return nil, NewError(ErrPayloadTooLarge, 1, "JSON payload size %d exceeds maximum %d bytes", len(raw), maxBytes)
	}
	if !utf8.Valid(raw) {
		return nil, NewError(ErrInvalidControlChar, 1, "raw JSON contains invalid UTF-8 bytes")
	}
	// Reject raw escaped \uFFFD or unpaired UTF-16 surrogates via token stream check.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	val, err := decodeStrictToken(dec, 0, rejectCaseCollision)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, NewError(ErrSchemaValidationFailed, 1, "trailing tokens after root JSON value")
	}
	return val, nil
}

func decodeStrictToken(dec *json.Decoder, depth int, rejectCaseCollision bool) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, NewError(ErrSchemaValidationFailed, 1, "malformed JSON: %v", err)
	}
	return decodeStrictValueFromToken(dec, tok, depth, rejectCaseCollision)
}

func decodeStrictValueFromToken(dec *json.Decoder, tok json.Token, depth int, rejectCaseCollision bool) (any, error) {
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			nextDepth := depth + 1
			if nextDepth > MaxJSONDepth {
				return nil, NewError(ErrMaxJSONDepthExceeded, 1, "JSON nesting depth exceeds %d", MaxJSONDepth)
			}
			obj := make(map[string]any)
			exactSeen := make(map[string]struct{})
			var lowerSeen map[string]string
			if rejectCaseCollision {
				lowerSeen = make(map[string]string)
			}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, NewError(ErrSchemaValidationFailed, 1, "malformed object key: %v", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, NewError(ErrSchemaValidationFailed, 1, "object key must be a string")
				}
				if err := ValidateSafeJSONString(key); err != nil {
					return nil, err
				}
				if _, dup := exactSeen[key]; dup {
					return nil, NewError(ErrDuplicateJSONKey, 1, "duplicate JSON object key %q", key)
				}
				exactSeen[key] = struct{}{}
				if rejectCaseCollision {
					lk := asciiLower(key)
					if prev, exists := lowerSeen[lk]; exists && prev != key {
						return nil, NewError(ErrCaseCollidingJSONKey, 1, "case-colliding JSON keys %q and %q", prev, key)
					}
					lowerSeen[lk] = key
				}
				elemVal, err := decodeStrictToken(dec, nextDepth, rejectCaseCollision)
				if err != nil {
					return nil, err
				}
				obj[key] = elemVal
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim('}') {
				return nil, NewError(ErrSchemaValidationFailed, 1, "unterminated JSON object")
			}
			return obj, nil

		case '[':
			nextDepth := depth + 1
			if nextDepth > MaxJSONDepth {
				return nil, NewError(ErrMaxJSONDepthExceeded, 1, "JSON nesting depth exceeds %d", MaxJSONDepth)
			}
			arr := make([]any, 0)
			for dec.More() {
				elemVal, err := decodeStrictToken(dec, nextDepth, rejectCaseCollision)
				if err != nil {
					return nil, err
				}
				arr = append(arr, elemVal)
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim(']') {
				return nil, NewError(ErrSchemaValidationFailed, 1, "unterminated JSON array")
			}
			return arr, nil

		default:
			return nil, NewError(ErrSchemaValidationFailed, 1, "unexpected delimiter %v", v)
		}

	case string:
		if err := ValidateSafeJSONString(v); err != nil {
			return nil, err
		}
		return v, nil

	case json.Number:
		s := string(v)
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, NewError(ErrInvalidJSONNumber, 1, "invalid JSON number %q", s)
		}
		if !strings.ContainsAny(s, ".eE") {
			iv, err := strconv.ParseInt(s, 10, 64)
			if err != nil || iv < MinSafeInt53 || iv > MaxSafeInt53 {
				return nil, NewError(ErrJSONIntegerPrecisionLoss, 1, "integer literal %q outside IEEE-754 int53 safe range", s)
			}
		}
		if f == 0 {
			f = 0.0 // normalize -0.0 to +0.0
		}
		return f, nil

	case bool:
		return v, nil

	case nil:
		return nil, nil

	default:
		return nil, NewError(ErrSchemaValidationFailed, 1, "unsupported JSON token %T", tok)
	}
}

// MarshalJCS serializes any JSON-compatible Go value into RFC 8785 Canonical JSON (JCS).
func MarshalJCS(v any) ([]byte, error) {
	norm, err := normalizeForJCS(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeJCSValue(&buf, norm); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalizeForJCS(v any) (any, error) {
	switch x := v.(type) {
	case nil, bool, string, float64, int, int64, uint64, json.Number, []any, map[string]any:
		return x, nil
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var out any
		if err := dec.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func writeJCSValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		writeJCSString(buf, x)
		return nil
	case float64:
		s, err := formatJCSFloat(x)
		if err != nil {
			return err
		}
		buf.WriteString(s)
		return nil
	case int:
		return writeJCSInt64(buf, int64(x))
	case int64:
		return writeJCSInt64(buf, x)
	case uint64:
		if x > uint64(MaxSafeInt53) {
			return fmt.Errorf("uint64 %d exceeds int53 safe range", x)
		}
		buf.WriteString(strconv.FormatUint(x, 10))
		return nil
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			iv, err := strconv.ParseInt(s, 10, 64)
			if err != nil || iv < MinSafeInt53 || iv > MaxSafeInt53 {
				return NewError(ErrJSONIntegerPrecisionLoss, 1, "integer literal %q outside IEEE-754 int53 safe range", s)
			}
			if iv == 0 {
				buf.WriteString("0")
			} else {
				buf.WriteString(strconv.FormatInt(iv, 10))
			}
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		fs, err := formatJCSFloat(f)
		if err != nil {
			return err
		}
		buf.WriteString(fs)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			norm, err := normalizeForJCS(elem)
			if err != nil {
				return err
			}
			if err := writeJCSValue(buf, norm); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			norm, err := normalizeForJCS(x[k])
			if err != nil {
				return err
			}
			if err := writeJCSValue(buf, norm); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		norm, err := normalizeForJCS(x)
		if err != nil {
			return err
		}
		return writeJCSValue(buf, norm)
	}
}

func writeJCSInt64(buf *bytes.Buffer, x int64) error {
	if x < MinSafeInt53 || x > MaxSafeInt53 {
		return fmt.Errorf("int64 %d outside int53 safe range", x)
	}
	if x == 0 {
		buf.WriteString("0")
		return nil
	}
	buf.WriteString(strconv.FormatInt(x, 10))
	return nil
}

// writeJCSString implements RFC 8785 §3.2.2.2 string escaping.
func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		if b < 0x20 {
			switch b {
			case '\b':
				buf.WriteString(`\b`)
			case '\t':
				buf.WriteString(`\t`)
			case '\n':
				buf.WriteString(`\n`)
			case '\f':
				buf.WriteString(`\f`)
			case '\r':
				buf.WriteString(`\r`)
			default:
				fmt.Fprintf(buf, `\u%04x`, b)
			}
			i++
			continue
		}
		if b == '"' {
			buf.WriteString(`\"`)
			i++
			continue
		}
		if b == '\\' {
			buf.WriteString(`\\`)
			i++
			continue
		}
		r, width := utf8.DecodeRuneInString(s[i:])
		buf.WriteRune(r)
		i += width
	}
	buf.WriteByte('"')
}

// formatJCSFloat formats an IEEE-754 float64 per RFC 8785 §3.2.2.3 (ECMAScript Number::toString).
func formatJCSFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("JCS forbids NaN or Infinity")
	}
	if f == 0 {
		return "0", nil
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	// Scientific notation with no leading zero on the exponent (e.g. 1e-7, 1e+21).
	s := strconv.FormatFloat(f, 'e', -1, 64)
	if idx := strings.IndexByte(s, 'e'); idx != -1 && len(s) >= idx+4 {
		sign := s[idx+1]
		exp := strings.TrimLeft(s[idx+2:], "0")
		if exp == "" {
			exp = "0"
		}
		return s[:idx+1] + string(sign) + exp, nil
	}
	return s, nil
}

// compareUTF16 compares two strings by their UTF-16 code unit sequence (RFC 8785 §3.2.3).
func compareUTF16(a, b string) int {
	if a == b {
		return 0
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	minLen := len(ua)
	if len(ub) < minLen {
		minLen = len(ub)
	}
	for i := 0; i < minLen; i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}

// FormatSafeTerminalASCII implements §4.6.4 JCS-first unambiguous terminal escaping:
// literal '\' becomes '\\', literal '"' becomes '\"', and any rune < 0x20 or >= 0x7F
// becomes \uXXXX / \UXXXXXXXX.
func FormatSafeTerminalASCII(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r < 0x20 || r >= 0x7F:
			if r <= 0xFFFF {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}
