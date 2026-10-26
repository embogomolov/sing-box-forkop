package option

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// A range wider than its type can count, as {"from": -2147483648, "to": 2147483647} is for a 32-bit
// router's int, panicked when a value was drawn, which XHTTP's pool does when the node is built.
func TestRangeAsWideAsItsType(t *testing.T) {
	for range 1000 {
		value := Range[int32]{From: math.MinInt32, To: math.MaxInt32}.Rand()
		require.Less(t, value, int32(math.MaxInt32))
		Range[int]{From: math.MinInt, To: math.MaxInt}.Rand()
		Range[uint64]{From: 0, To: math.MaxUint64}.Rand()
		value = Range[int32]{From: -3, To: 2}.Rand()
		require.GreaterOrEqual(t, value, int32(-3))
		require.Less(t, value, int32(2))
	}
}
