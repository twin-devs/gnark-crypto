// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by consensys/gnark-crypto DO NOT EDIT

package twistededwards

import (
	"crypto/subtle"
	"io"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// PointAffine point on a twisted Edwards curve
type PointAffine struct {
	X, Y fr.Element
}

// PointProj point in projective coordinates
type PointProj struct {
	X, Y, Z fr.Element
}

const (
	//following https://tools.ietf.org/html/rfc8032#section-3.1,
	// an fr element x is negative if its binary encoding is
	// lexicographically larger than -x.
	mCompressedNegative = 0x80
	mCompressedPositive = 0x00
	mUnmask             = 0x7f

	// size in byte of a compressed point (point.Y --> fr.Element)
	sizePointCompressed = fr.Limbs * 8
)

// Bytes returns the compressed point as a byte array
// Follows https://tools.ietf.org/html/rfc8032#section-3.1,
// as the twisted Edwards implementation is primarily used
// for eddsa.
func (p *PointAffine) Bytes() [sizePointCompressed]byte {

	var res [sizePointCompressed]byte
	var mask uint

	y := p.Y.Bytes()

	if p.X.LexicographicallyLargest() {
		mask = mCompressedNegative
	} else {
		mask = mCompressedPositive
	}
	// p.Y must be in little endian
	y[0] |= byte(mask) // msb of y
	for i, j := 0, sizePointCompressed-1; i < j; i, j = i+1, j-1 {
		y[i], y[j] = y[j], y[i]
	}
	subtle.ConstantTimeCopy(1, res[:], y[:])
	return res
}

// Marshal converts p to a byte slice
func (p *PointAffine) Marshal() []byte {
	b := p.Bytes()
	return b[:]
}

func computeX(y *fr.Element) (x fr.Element) {
	var one, num, den fr.Element
	one.SetOne()
	num.Square(y)
	den.Mul(&num, &edwards.D)
	num.Sub(&one, &num)
	den.Sub(&edwards.A, &den)
	x.Div(&num, &den)
	x.Sqrt(&x)
	return
}

// SetBytes sets p from buf
// len(buf) >= sizePointCompressed
// buf contains the Y coordinate masked with a parity bit to recompute the X coordinate
// from the curve equation. See Bytes() and https://tools.ietf.org/html/rfc8032#section-3.1
// Returns the number of read bytes and an error if the buffer is too short.
func (p *PointAffine) SetBytes(buf []byte) (int, error) {

	if len(buf) < sizePointCompressed {
		return 0, io.ErrShortBuffer
	}
	bufCopy := make([]byte, sizePointCompressed)
	subtle.ConstantTimeCopy(1, bufCopy, buf[:sizePointCompressed])
	for i, j := 0, sizePointCompressed-1; i < j; i, j = i+1, j-1 {
		bufCopy[i], bufCopy[j] = bufCopy[j], bufCopy[i]
	}
	isLexicographicallyLargest := (mCompressedNegative&bufCopy[0])>>7 == 1
	bufCopy[0] &= mUnmask
	p.Y.SetBytes(bufCopy)
	p.X = computeX(&p.Y)
	if isLexicographicallyLargest {
		if !p.X.LexicographicallyLargest() {
			p.X.Neg(&p.X)
		}
	} else {
		if p.X.LexicographicallyLargest() {
			p.X.Neg(&p.X)
		}
	}

	return sizePointCompressed, nil
}

// Unmarshal alias to SetBytes()
func (p *PointAffine) Unmarshal(b []byte) error {
	_, err := p.SetBytes(b)
	return err
}

// Set sets p to p1 and return it
func (p *PointProj) Set(p1 *PointProj) *PointProj {
	p.X.Set(&p1.X)
	p.Y.Set(&p1.Y)
	p.Z.Set(&p1.Z)
	return p
}

// Set sets p to p1 and return it
func (p *PointAffine) Set(p1 *PointAffine) *PointAffine {
	p.X.Set(&p1.X)
	p.Y.Set(&p1.Y)
	return p
}

// Equal returns true if p=p1 false otherwise
func (p *PointAffine) Equal(p1 *PointAffine) bool {
	return p.X.Equal(&p1.X) && p.Y.Equal(&p1.Y)
}

// Equal returns true if p=p1 false otherwise
// If one point is on the affine chart Z=0 it returns false
func (p *PointProj) Equal(p1 *PointProj) bool {
	if p.Z.IsZero() || p1.Z.IsZero() {
		return false
	}
	var pAffine, p1Affine PointAffine
	pAffine.FromProj(p)
	p1Affine.FromProj(p1)
	return pAffine.Equal(&p1Affine)
}

// NewPointAffine creates a new instance of PointAffine
func NewPointAffine(x, y fr.Element) PointAffine {
	return PointAffine{x, y}
}

// IsOnCurve checks if a point is on the twisted Edwards curve
func (p *PointAffine) IsOnCurve() bool {

	ecurve := GetEdwardsCurve()

	var lhs, rhs, tmp fr.Element

	tmp.Mul(&p.Y, &p.Y)
	lhs.Mul(&p.X, &p.X).
		Neg(&lhs).
		Add(&lhs, &tmp)

	tmp.Mul(&p.X, &p.X).
		Mul(&tmp, &p.Y).
		Mul(&tmp, &p.Y).
		Mul(&tmp, &ecurve.D)
	rhs.SetOne().Add(&rhs, &tmp)

	return lhs.Equal(&rhs)
}

// Add adds two points (x,y), (u,v) on a twisted Edwards curve with parameters a, d
// modifies p
func (p *PointAffine) Add(p1, p2 *PointAffine) *PointAffine {

	ecurve := GetEdwardsCurve()

	var xu, yv, xv, yu, dxyuv, one, denx, deny fr.Element
	pRes := new(PointAffine)
	xv.Mul(&p1.X, &p2.Y)
	yu.Mul(&p1.Y, &p2.X)
	pRes.X.Add(&xv, &yu)

	xu.Mul(&p1.X, &p2.X)
	yv.Mul(&p1.Y, &p2.Y)
	pRes.Y.Add(&yv, &xu)

	dxyuv.Mul(&xv, &yu).Mul(&dxyuv, &ecurve.D)
	one.SetOne()
	denx.Add(&one, &dxyuv)
	deny.Sub(&one, &dxyuv)

	p.X.Div(&pRes.X, &denx)
	p.Y.Div(&pRes.Y, &deny)

	return p
}

// Double doubles point (x,y) on a twisted Edwards curve with parameters a, d
// modifies p
func (p *PointAffine) Double(p1 *PointAffine) *PointAffine {

	p.Set(p1)
	var xx, yy, xy, denum, two fr.Element
	xx.Square(&p.X)
	yy.Square(&p.Y)
	xy.Mul(&p.X, &p.Y)
	denum.Sub(&yy, &xx)

	p.X.Double(&xy).Div(&p.X, &denum)

	two.SetOne().Double(&two)
	denum.Neg(&denum).Add(&denum, &two)

	p.Y.Add(&xx, &yy).Div(&p.Y, &denum)

	return p
}

// Neg negates point (x,y) on a twisted Edwards curve with parameters a, d
// modifies p
func (p *PointAffine) Neg(p1 *PointAffine) *PointAffine {
	p.Set(p1)
	p.X.Neg(&p1.X)
	return p
}

// FromProj sets p in affine from p in projective
func (p *PointAffine) FromProj(p1 *PointProj) *PointAffine {
	p.X.Div(&p1.X, &p1.Z)
	p.Y.Div(&p1.Y, &p1.Z)
	return p
}

// FromAffine sets p in projective from p in affine
func (p *PointProj) FromAffine(p1 *PointAffine) *PointProj {
	p.X.Set(&p1.X)
	p.Y.Set(&p1.Y)
	p.Z.SetOne()
	return p
}

// Add adds points in projective coordinates
// cf https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
func (p *PointProj) Add(p1, p2 *PointProj) *PointProj {

	var res PointProj

	ecurve := GetEdwardsCurve()

	var A, B, C, D, E, F, G, H, I fr.Element
	A.Mul(&p1.Z, &p2.Z)
	B.Square(&A)
	C.Mul(&p1.X, &p2.X)
	D.Mul(&p1.Y, &p2.Y)
	E.Mul(&ecurve.D, &C).Mul(&E, &D)
	F.Sub(&B, &E)
	G.Add(&B, &E)
	H.Add(&p1.X, &p1.Y)
	I.Add(&p2.X, &p2.Y)
	res.X.Mul(&H, &I).
		Sub(&res.X, &C).
		Sub(&res.X, &D).
		Mul(&res.X, &p1.Z).
		Mul(&res.X, &F)
	res.Y.Add(&D, &C).
		Mul(&res.Y, &p.Z).
		Mul(&res.Y, &G)
	res.Z.Mul(&F, &G)

	p.Set(&res)
	return p
}

// Double adds points in projective coordinates
// cf https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
func (p *PointProj) Double(p1 *PointProj) *PointProj {

	var res PointProj

	var B, C, D, E, F, H, J, tmp fr.Element

	B.Add(&p1.X, &p1.Y).Square(&B)
	C.Square(&p1.X)
	D.Square(&p1.Y)
	E.Neg(&C)
	F.Add(&E, &D)
	H.Square(&p1.Z)
	tmp.Double(&H)
	J.Sub(&F, &tmp)
	res.X.Sub(&B, &C).
		Sub(&res.X, &D).
		Mul(&res.X, &J)
	res.Y.Sub(&E, &D).Mul(&res.Y, &F)
	res.Z.Mul(&F, &J)

	p.Set(&res)
	return p
}

// Neg sets p to -p1 and returns it
func (p *PointProj) Neg(p1 *PointProj) *PointProj {
	p.X.Neg(&p1.X)
	return p
}

// ScalarMul scalar multiplication of a point
// p1 points on the twisted Edwards curve
// c parameters of the twisted Edwards curve
// scal scalar NOT in Montgomery form
// modifies p
//func (p *PointAffine) ScalarMul(p1 *PointAffine, scalar fr.Element) *PointAffine {
func (p *PointAffine) ScalarMul(p1 *PointAffine, scalar *big.Int) *PointAffine {

	var _scalar big.Int
	_scalar.Set(scalar)

	p.Set(p1)

	if _scalar.Sign() == -1 {
		_scalar.Neg(&_scalar)
		p.Neg(p)
	}

	var resProj, p1Proj PointProj
	resProj.X.SetZero()
	resProj.Y.SetOne()
	resProj.Z.SetOne()

	p1Proj.FromAffine(p)

	const wordSize = bits.UintSize

	sWords := _scalar.Bits()

	for i := len(sWords) - 1; i >= 0; i-- {
		ithWord := sWords[i]
		for k := 0; k < wordSize; k++ {
			resProj.Double(&resProj)
			kthBit := (ithWord >> (wordSize - 1 - k)) & 1
			if kthBit == 1 {
				resProj.Add(&resProj, &p1Proj)
			}
		}
	}

	p.FromProj(&resProj)

	return p
}
