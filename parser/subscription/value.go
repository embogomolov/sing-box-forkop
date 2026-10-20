package subscription

import (
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// The scalar types below read the shapes generators write: quoted numbers, 0 and 1 for booleans,
// single-element lists collapsed into a string.

// Port is a server port written as a number or as a string.
type Port uint16

func (p *Port) UnmarshalJSON(content []byte) error {
	number, err := unmarshalNumber(content)
	if err != nil {
		return err
	}
	if number < 1 || number > 65535 {
		return E.New("port out of range: ", number)
	}
	*p = Port(number)
	return nil
}

func (p Port) String() string {
	return strconv.FormatUint(uint64(p), 10)
}

// Int is an integer written as a number or as a string.
type Int int64

func (i *Int) UnmarshalJSON(content []byte) error {
	number, err := unmarshalNumber(content)
	if err != nil {
		return err
	}
	*i = Int(number)
	return nil
}

func (i Int) String() string {
	return strconv.FormatInt(int64(i), 10)
}

// Value returns the integer, refusing one that does not fit the platform int.
func (i Int) Value(name string) (int, error) {
	converted := int(i)
	if int64(converted) != int64(i) {
		return 0, E.New(name, " is out of range: ", int64(i))
	}
	return converted, nil
}

func unmarshalNumber(content []byte) (int64, error) {
	var number int64
	if err := json.Unmarshal(content, &number); err == nil {
		return number, nil
	}
	var text string
	if err := json.Unmarshal(content, &text); err != nil {
		return 0, err
	}
	text = strings.TrimSpace(text)
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, E.New("invalid number: ", text)
	}
	return number, nil
}

// Bool is a boolean written as a boolean, as 0 and 1, or as text.
type Bool struct {
	value bool
}

func (b Bool) Value() bool {
	return b.value
}

func (b *Bool) UnmarshalJSON(content []byte) error {
	var value bool
	if err := json.Unmarshal(content, &value); err == nil {
		b.value = value
		return nil
	}
	var number int64
	if err := json.Unmarshal(content, &number); err == nil {
		b.value = number != 0
		return nil
	}
	var text string
	if err := json.Unmarshal(content, &text); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "1", "true", "yes", "on":
		b.value = true
	case "0", "false", "no", "off", "":
		b.value = false
	default:
		return E.New("invalid boolean: ", text)
	}
	return nil
}

// StringList is a list written as a list or as one comma-separated string.
type StringList []string

func (l *StringList) UnmarshalJSON(content []byte) error {
	var values []string
	if err := json.Unmarshal(content, &values); err == nil {
		*l = trimStrings(values)
		return nil
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return err
	}
	*l = trimStrings(strings.Split(value, ","))
	return nil
}

func trimStrings(values []string) []string {
	var result []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

// IsSet reports whether a decoded option block carries anything at all. A
// document routinely writes an option block out empty, and an empty block says
// nothing about how to connect - only a block with a value in it does.
func IsSet(value any) bool {
	return isSetValue(reflect.ValueOf(value))
}

func isSetValue(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		return !value.IsNil() && isSetValue(value.Elem())
	case reflect.Map, reflect.Slice, reflect.String:
		return value.Len() != 0
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if isSetValue(value.Field(index)) {
				return true
			}
		}
		return false
	default:
		return !value.IsZero()
	}
}

// CheckVLESSFlow refuses a VLESS flow sing-box cannot speak. The flow decides
// how the payload is framed after the handshake, and it is announced to the
// server, so a client that quietly drops it is answered by a server still
// framing its side the other way.
func CheckVLESSFlow(flow string) error {
	switch flow {
	case "", "xtls-rprx-vision":
		return nil
	}
	return E.New("unsupported VLESS flow: ", flow)
}

// String is a text field a generator may have written as a number or a boolean, as Clash reads its
// configuration weakly typed.
type String string

func (s *String) UnmarshalJSON(content []byte) error {
	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		*s = String(text)
		return nil
	}
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case nil:
		*s = ""
	case float64:
		*s = String(strconv.FormatFloat(typed, 'f', -1, 64))
	case bool:
		*s = String(strconv.FormatBool(typed))
	default:
		return E.New("expected a string")
	}
	return nil
}

func (s String) String() string {
	return string(s)
}

// QUICSecurity drops what a QUIC handshake cannot carry: uTLS and Reality, which sing-box refuses
// there, though Clash and Xray write a client fingerprint beside every TLS field.
func QUICSecurity(options *option.OutboundTLSOptions) *option.OutboundTLSOptions {
	if options == nil {
		return nil
	}
	options.UTLS = nil
	options.Reality = nil
	return options
}

// VLESSEncryption maps "none" to the empty field, as sing-box means it, so a server imported from
// any format comes out identical.
func VLESSEncryption(encryption string) string {
	if encryption == "none" {
		return ""
	}
	return encryption
}

// PortRanges reads a port hopping list - "443,20000-30000", with slashes in
// place of the commas in some documents - as the ranges sing-box takes. A single
// port is written as a range of one, since sing-box refuses an entry without a
// colon.
func PortRanges(ports string) badoption.Listable[string] {
	var result badoption.Listable[string]
	for _, port := range strings.Split(strings.ReplaceAll(ports, "/", ","), ",") {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		start, end, isRange := strings.Cut(port, "-")
		if !isRange {
			end = start
		}
		result = append(result, strings.TrimSpace(start)+":"+strings.TrimSpace(end))
	}
	return result
}

// Headers turns the single-valued header map subscriptions write into the one
// sing-box takes.
func Headers(source map[string]string) badoption.HTTPHeader {
	if len(source) == 0 {
		return nil
	}
	header := make(badoption.HTTPHeader, len(source))
	for key, value := range source {
		header[key] = []string{value}
	}
	return header
}

// HopInterval reads a Hysteria 2 hop interval written as a number of seconds, a
// duration, or a range of either.
func HopInterval(value string) (badoption.Duration, badoption.Duration, error) {
	lower, upper, isRange := strings.Cut(strings.TrimSpace(value), "-")
	minimum := hopIntervalBound(lower)
	if !isRange {
		return minimum, 0, nil
	}
	maximum := hopIntervalBound(upper)
	if minimum <= 0 || maximum < minimum {
		return 0, 0, E.New("invalid Hysteria 2 hop interval range: ", value)
	}
	return minimum, maximum, nil
}

func hopIntervalBound(value string) badoption.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return badoption.Duration(time.Duration(seconds) * time.Second)
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return badoption.Duration(duration)
}
