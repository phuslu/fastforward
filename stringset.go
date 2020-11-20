package main

import (
	"strings"
)

type StringSet map[string]struct{}

func NewStringSet(ss []string) (m StringSet) {
	for _, s := range ss {
		if m == nil {
			m = make(StringSet)
		}
		m[s] = struct{}{}
	}
	return
}

func NewUpperStringSet(ss []string) (m StringSet) {
	for _, s := range ss {
		if m == nil {
			m = make(StringSet)
		}
		m[strings.ToUpper(s)] = struct{}{}
	}
	return
}

func NewLowerStringSet(ss []string) (m StringSet) {
	for _, s := range ss {
		if m == nil {
			m = make(StringSet)
		}
		m[strings.ToLower(s)] = struct{}{}
	}
	return
}

func (m StringSet) Join(c byte) string {
	var b strings.Builder
	i := 0
	for s := range m {
		if i > 0 {
			b.WriteByte(c)
		}
		b.WriteString(s)
	}
	return b.String()
}

func (m StringSet) Contains(s string) (ok bool) {
	_, ok = m[s]
	return
}

func (m StringSet) Insert(s string) {
	m[s] = struct{}{}
}

func (m StringSet) Clear() {
	for k := range m {
		delete(m, k)
	}
}

func (m0 StringSet) Overlapped(m StringSet) (ok bool) {
	for k := range m0 {
		if _, ok = m[k]; ok {
			return
		}
	}
	return
}

func (m StringSet) OverlappedSlice(a []string) (ok bool) {
	for _, k := range a {
		if _, ok = m[k]; ok {
			return
		}
	}
	return
}

func (m StringSet) OverlappedBytesSlice(a [][]byte) (ok bool) {
	for _, k := range a {
		if _, ok = m[string(k)]; ok {
			return
		}
	}
	return
}

func (m StringSet) Size() int {
	return len(m)
}

func (m StringSet) Empty() bool {
	return len(m) == 0
}

func (m StringSet) Slice() (a []string) {
	for k := range m {
		a = append(a, k)
	}
	return
}
