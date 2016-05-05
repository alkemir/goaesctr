// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Modified by Bryan Reynaert on 2016 to add ReaderAt interface.

// Counter (CTR) mode.

// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.

// See NIST SP 800-38A, pp 13-15

package aesctr

import (
	"crypto/cipher"
	"io"
	"sync"
)

type ctr struct {
	b       cipher.Block
	iv      []byte
	ctr     []byte
	out     []byte
	outUsed int

	r  io.ReaderAt
	rl sync.Mutex
}

const streamBufferSize = 512

// NewCTRReaderAt returns a ReaderAt which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as the Block's block size.
func NewCTRReaderAt(block cipher.Block, iv []byte, reader io.ReaderAt) io.ReaderAt {
	if len(iv) != block.BlockSize() {
		panic("cipher.NewCTR: IV length must equal block size")
	}
	bufSize := streamBufferSize
	if bufSize < block.BlockSize() {
		bufSize = block.BlockSize()
	}
	return &ctr{
		b:       block,
		iv:      dup(iv),
		ctr:     dup(iv),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
		r:       reader,
	}
}

func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	bs := x.b.BlockSize()
	for remain <= len(x.out)-bs {
		x.b.Encrypt(x.out[remain:], x.ctr)
		remain += bs

		// Increment counter
		for i := len(x.ctr) - 1; i >= 0; i-- {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			x.refill()
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}

func (x *ctr) ReadAt(p []byte, off int64) (n int, err error) {
	// Read from start of block
	bOff := off % int64(x.b.BlockSize())
	bStart := off - bOff
	bN := bStart / int64(x.b.BlockSize())

	x.rl.Lock()
	defer x.rl.Unlock()

	x.setCTR(bN) // We could have a different buffer for each reader

	n, err = x.r.ReadAt(p, off)
	if err != nil {
		return
	}

	x.XORKeyStream(p, p)
	return
}

// Utility routines

func (x *ctr) setCTR(bN int64) {
	x.outUsed = 0

	// Fill ctr
	// TODO (br): This can be greatly improved, it is just for correctness testing
	copy(x.ctr, x.iv)
	for j := int64(0); j < bN; j++ {
		for i := len(x.ctr) - 1; i >= 0; i-- {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}

	// Fill out
	remain := 0
	bs := x.b.BlockSize()
	for remain <= len(x.out)-bs {
		x.b.Encrypt(x.out[remain:], x.ctr)
		remain += bs

		// Increment counter
		for i := len(x.ctr) - 1; i >= 0; i-- {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}

	x.out = x.out[:remain]
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}

func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
