// Package domainset builds the domain matcher of sing (common/domain) bit for bit without the
// queue of the whole breadth-first walk domain.NewMatcher keeps, a node of the trie each: the
// walk keeps one level and the next, and the trie goes to sing as a binary rule set carries it.
package domainset

import (
	"bytes"
	"encoding/binary"
	"slices"
	"unicode/utf8"

	"github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"
)

// the labels of sing (common/domain/matcher.go) that end a suffix, and a name with its subdomains
const (
	prefixLabel = '\r'
	rootLabel   = '\n'
)

// NewMatcher is domain.NewMatcher(domains, domainSuffix, false). The lists hold no empty name
// and are not both empty, as sing requires too.
func NewMatcher(domains []string, domainSuffix []string) (*domain.Matcher, error) {
	return domain.ReadMatcher(bytes.NewReader(encode(domains, domainSuffix)))
}

func encode(domains []string, domainSuffix []string) []byte {
	return build(keys(domains, domainSuffix))
}

// keys are the keys of the trie as domain.NewMatcher makes them, sorted and each once.
func keys(domains []string, domainSuffix []string) []string {
	seen := make(map[string]bool, len(domainSuffix)+len(domains))
	list := make([]string, 0, len(domains)+len(domainSuffix))
	for _, name := range domainSuffix {
		if seen[name] {
			continue
		}
		seen[name] = true
		if name[0] == '.' {
			list = append(list, reverse(string(prefixLabel)+name))
		} else {
			list = append(list, reverse(string(rootLabel)+name))
		}
	}
	for _, name := range domains {
		if seen[name] {
			continue
		}
		seen[name] = true
		list = append(list, reverse(name))
	}
	slices.Sort(list)
	return slices.Compact(list)
}

// reverse is reverseDomain of sing: the runes in the other order.
func reverse(name string) string {
	length := len(name)
	reversed := make([]byte, length)
	for index := 0; index < length; {
		character, size := utf8.DecodeRuneInString(name[index:])
		index += size
		utf8.EncodeRune(reversed[length-index:], character)
	}
	return string(reversed)
}

// span is a node of the trie: the keys from start to end, which share their first column bytes.
type span struct {
	start, end, column int32
}

// build makes the trie of newSuccinctSet of sing from sorted distinct keys, written as
// succinctSet.Write writes it, walking it a level at a time in the order of sing's walk.
func build(keys []string) []byte {
	var (
		leaves, labelBitmap []uint64
		labels              []byte
	)
	setBit := func(words *[]uint64, index int) {
		for index>>6 >= len(*words) {
			*words = append(*words, 0)
		}
		(*words)[index>>6] |= 1 << uint(index&63)
	}
	bit, node := 0, 0
	level := []span{{0, int32(len(keys)), 0}}
	var next []span
	for len(level) > 0 {
		next = next[:0]
		for _, item := range level {
			start, column := int(item.start), int(item.column)
			if column == len(keys[start]) {
				start++
				setBit(&leaves, node)
			}
			for index := start; index < int(item.end); {
				first := index
				for index < int(item.end) && keys[index][column] == keys[first][column] {
					index++
				}
				next = append(next, span{int32(first), int32(index), int32(column + 1)})
				labels = append(labels, keys[first][column])
				bit++
			}
			setBit(&labelBitmap, bit)
			bit++
			node++
		}
		level, next = next, level
	}
	var content bytes.Buffer
	content.Grow(16 + 8*(len(leaves)+len(labelBitmap)) + len(labels))
	content.WriteByte(0)
	writeWords(&content, leaves)
	writeWords(&content, labelBitmap)
	_, _ = varbin.WriteUvarint(&content, uint64(len(labels)))
	content.Write(labels)
	return content.Bytes()
}

func writeWords(content *bytes.Buffer, words []uint64) {
	_, _ = varbin.WriteUvarint(content, uint64(len(words)))
	var word [8]byte
	for _, value := range words {
		binary.BigEndian.PutUint64(word[:], value)
		content.Write(word[:])
	}
}
