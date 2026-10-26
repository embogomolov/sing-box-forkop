package option

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

type Range[T Integer] struct {
	From T `json:"from"`
	To   T `json:"to"`
}

func (c *Range[T]) MarshalJSON() ([]byte, error) {
	if c.From == c.To {
		return json.Marshal(c.From)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", c.From, c.To))
}

func (c *Range[T]) UnmarshalJSON(content []byte) error {
	var stringValue string
	if err := json.Unmarshal(content, &stringValue); err == nil {
		parts := strings.Split(stringValue, "-")
		switch len(parts) {
		case 1:
			v, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return err
			}
			c.From, c.To = T(v), T(v)
		case 2:
			from, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return err
			}
			to, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return err
			}
			c.From, c.To = T(from), T(to)
		default:
			return E.New("invalid range: ", stringValue)
		}
	} else {
		var single T
		if err := json.Unmarshal(content, &single); err == nil {
			c.From, c.To = single, single
		} else {
			type plain struct {
				From T `json:"from"`
				To   T `json:"to"`
			}
			var p plain
			if err := json.Unmarshal(content, &p); err != nil {
				return err
			}
			c.From, c.To = p.From, p.To
		}
	}
	if c.From > c.To {
		return E.New("invalid range")
	}
	return nil
}

func (c *Range[T]) String() string {
	if c.From == c.To {
		return fmt.Sprintf("%d", c.From)
	}
	return fmt.Sprintf("%d-%d", c.From, c.To)
}

func (c Range[T]) Rand() T {
	if c.From == c.To {
		return c.From
	}
	// in uint64: the width of a range may be more than T can hold
	bigInt, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(uint64(c.To)-uint64(c.From)))
	return c.From + T(bigInt.Uint64())
}
