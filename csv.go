package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

type CSVHeader map[string]int

func NewCSVHeader(record []string) (header CSVHeader) {
	header = make(map[string]int, len(record))
	for i, s := range record {
		header[s] = i
	}
	return
}

func (h CSVHeader) GetString(record []string, name string) (value string) {
	if i, ok := h[name]; ok && i < len(record) {
		value = record[i]
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetLowerString(record []string, name string) (value string) {
	if i, ok := h[name]; ok && i < len(record) {
		value = strings.ToLower(record[i])
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetUint32(record []string, name string) (value uint32) {
	if i, ok := h[name]; ok && i < len(record) {
		n, _ := strconv.ParseUint(record[i], 10, 32)
		value = uint32(n)
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetUint64(record []string, name string) (value uint64) {
	if i, ok := h[name]; ok && i < len(record) {
		value, _ = strconv.ParseUint(record[i], 10, 64)
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetFloat64(record []string, name string) (value float64) {
	if i, ok := h[name]; ok && i < len(record) {
		value, _ = strconv.ParseFloat(record[i], 64)
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetStringSlice(record []string, name string, sep string) (value []string) {
	if i, ok := h[name]; ok && i < len(record) {
		if record[i] != "" {
			return strings.Split(record[i], sep)
		}
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetLowerStringSlice(record []string, name string, sep string) (value []string) {
	if i, ok := h[name]; ok && i < len(record) {
		if record[i] != "" {
			for _, s := range strings.Split(record[i], sep) {
				value = append(value, strings.ToLower(s))
			}
		}
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetUint32Slice(record []string, name string, sep string) (a []uint32) {
	if i, ok := h[name]; ok && i < len(record) {
		var err error
		var n uint64
		for _, s := range strings.Split(record[i], sep) {
			if s == "" {
				continue
			}
			n, err = strconv.ParseUint(s, 10, 32)
			if err != nil {
				panic(err)
			}
			a = append(a, uint32(n))
		}
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetUint64Slice(record []string, name string, sep string) (a []uint64) {
	if i, ok := h[name]; ok && i < len(record) {
		var err error
		var n uint64
		for _, s := range strings.Split(record[i], sep) {
			if s == "" {
				continue
			}
			n, err = strconv.ParseUint(s, 10, 64)
			if err != nil {
				panic(err)
			}
			a = append(a, n)
		}
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func (h CSVHeader) GetFloat64Slice(record []string, name string, sep string) (a []float64) {
	if i, ok := h[name]; ok && i < len(record) {
		var err error
		var n float64
		for _, s := range strings.Split(record[i], sep) {
			if s == "" {
				continue
			}
			n, err = strconv.ParseFloat(s, 64)
			if err != nil {
				panic(err)
			}
			a = append(a, n)
		}
	} else {
		panic("no name=[" + name + "] in record")
	}
	return
}

func ScanTarballCSV(body []byte, scan func(string, CSVHeader, []string)) error {
	var tr *tar.Reader
	switch {
	case bytes.HasPrefix(body, []byte{0x1f, 0x8b, 0x08}):
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return err
		}
		tr = tar.NewReader(gr)
	default:
		tr = tar.NewReader(bytes.NewReader(body))
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		// parse as csv file
		r := csv.NewReader(tr)
		record, err := r.Read()
		if err != nil {
			continue
		}
		header := NewCSVHeader(record)
		for {
			record, err = r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			scan(hdr.Name, header, record)
		}
	}
	return nil
}

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

type Uint32Set map[uint32]struct{}

func NewUint32Set(a []uint32) (m Uint32Set) {
	for _, i := range a {
		if m == nil {
			m = make(Uint32Set)
		}
		m[i] = struct{}{}
	}
	return
}

func (m Uint32Set) Empty() bool {
	return len(m) == 0
}

func (m Uint32Set) Size() int {
	return len(m)
}

func (m Uint32Set) Insert(n uint32) {
	m[n] = struct{}{}
}

func (m Uint32Set) Clear() {
	for k := range m {
		delete(m, k)
	}
}

func (m Uint32Set) Contains(n uint32) (ok bool) {
	_, ok = m[n]
	return
}

func (m0 Uint32Set) Overlapped(m Uint32Set) (ok bool) {
	for k := range m0 {
		if _, ok = m[k]; ok {
			return
		}
	}
	return
}

func (m Uint32Set) OverlappedSlice(a []uint32) (ok bool) {
	for _, k := range a {
		if _, ok = m[k]; ok {
			return
		}
	}
	return
}
