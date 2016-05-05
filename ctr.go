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
)

type ctr struct {
	b  cipher.Block
	iv []byte
	bs int

	r io.ReaderAt
}

type ctrState struct {
	ctr     []byte
	out     []byte
	outUsed int
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
		b:  block,
		iv: dup(iv),
		bs: bufSize,
		r:  reader,
	}
}

func (x *ctrState) refill(c *ctr) {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	bs := c.b.BlockSize()
	for remain <= len(x.out)-bs {
		c.b.Encrypt(x.out[remain:], x.ctr)
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

func (x *ctrState) XORKeyStream(dst, src []byte, c *ctr) {
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-c.b.BlockSize() {
			x.refill(c)
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}

func (c *ctr) ReadAt(p []byte, off int64) (n int, err error) {
	// ctrState to read from start of block
	bOff := off % int64(c.b.BlockSize())
	bStart := off - bOff
	bN := bStart / int64(c.b.BlockSize())

	state := initCTR(c, bN, bOff)

	n, err = c.r.ReadAt(p, off)
	if err != nil {
		return
	}

	state.XORKeyStream(p, p, c)
	return
}

func initCTR(c *ctr, bN, bOff int64) *ctrState {
	x := &ctrState{
		ctr:     dup(c.iv),
		out:     make([]byte, 0, c.bs),
		outUsed: 0,
	}

	// Fill ctr
	copy(x.ctr, c.iv)

	for i := len(x.ctr) - 1; bN != 0 && i >= 0; i-- {
		mod := byte(bN % 256)
		bN >>= 8

		tmp := x.ctr[i]
		x.ctr[i] += mod
		if x.ctr[i] < tmp { // carry over
			bN++
		}
	}

	x.refill(c)
	x.out = x.out[bOff:]
	return x
}

// Utility routines

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
