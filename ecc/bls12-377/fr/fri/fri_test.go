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

package fri

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// conversion of indices from ordered to canonical, _n is the size of the slice
// _p is the index to convert. It returns g^u, g^v where {g^u, g^v} is the fiber
// of g^(2*_p)
func convert(_p, _n int) (_u, _v big.Int) {
	if _p%2 == 0 {
		_u.SetInt64(int64(_p / 2))
		_v.SetInt64(int64(_p/2 + _n/2))
	} else {
		l := (_n - 1 - _p) / 2
		_u.SetInt64(int64(_n - 1 - l))
		_v.SetInt64(int64(_n - 1 - l - _n/2))
	}
	return
}

func randomPolynomial(size uint64, seed int32) []fr.Element {
	p := make([]fr.Element, size)
	p[0].SetUint64(uint64(seed))
	for i := 1; i < len(p); i++ {
		p[i].Square(&p[i-1])
	}
	return p
}

func TestFRI(t *testing.T) {

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 10

	properties := gopter.NewProperties(parameters)

	size := 4096

	properties.Property("verifying wrong opening should fail", prop.ForAll(

		func(m int32) bool {

			_s := RADIX_2_FRI.New(uint64(size), sha256.New())
			s := _s.(radixTwoFri)

			p := randomPolynomial(uint64(size), m)

			pos := int64(m % 4096)
			pp, _ := s.BuildProofOfProximity(p)

			openingProof := s.Open(p, uint64(pos))

			// check the Merkle path
			tamperedPosition := pos + 1
			err := s.VerifyOpening(uint64(tamperedPosition), openingProof, pp)

			return err != nil

		},
		gen.Int32Range(0, int32(rho*size)),
	))

	properties.Property("verifying correct opening should succeed", prop.ForAll(

		func(m int32) bool {

			_s := RADIX_2_FRI.New(uint64(size), sha256.New())
			s := _s.(radixTwoFri)

			p := randomPolynomial(uint64(size), m)

			pos := uint64(m % int32(size))
			pp, _ := s.BuildProofOfProximity(p)

			openingProof := s.Open(p, uint64(pos))

			// check the Merkle path
			err := s.VerifyOpening(uint64(pos), openingProof, pp)

			return err == nil

		},
		gen.Int32Range(0, int32(rho*size)),
	))

	properties.Property("The claimed value of a polynomial should match P(x)", prop.ForAll(
		func(m int32) bool {

			_s := RADIX_2_FRI.New(uint64(size), sha256.New())
			s := _s.(radixTwoFri)

			p := randomPolynomial(uint64(size), m)

			// check the opening value
			var g fr.Element
			pos := int64(m % 4096)
			g.Set(&s.domains[0].Generator)
			g.Exp(g, big.NewInt(pos))

			var val fr.Element
			for i := len(p) - 1; i >= 0; i-- {
				val.Mul(&val, &g)
				val.Add(&p[i], &val)
			}

			openingProof := s.Open(p, uint64(pos))
			var claimedValue fr.Element
			claimedValue.SetBytes(openingProof.proofSet[0])

			return claimedValue.Equal(&val)

		},
		gen.Int32Range(0, int32(rho*size)),
	))

	properties.Property("Derive queries position: points should belong the same fiber", prop.ForAll(

		func(m int32) bool {

			_s := RADIX_2_FRI.New(uint64(size), sha256.New())
			s := _s.(radixTwoFri)

			var r, g fr.Element

			_m := big.NewInt(int64(m))
			r.Exp(s.domains[0].Generator, _m)
			pos := s.deriveQueriesPositions(r)
			g.Set(&s.domains[0].Generator)
			n := int(s.domains[0].Cardinality)

			for i := 0; i < len(pos); i++ {

				u, v := convert(pos[i], n)

				var g1, g2 fr.Element
				g1.Exp(g, &u).Square(&g1)
				g2.Exp(g, &v).Square(&g2)

				if !g1.Equal(&g2) {
					return false
				}
				g.Square(&g)
				n = n >> 1
			}
			return true
		},
		gen.Int32Range(0, int32(rho*size)),
	))

	properties.Property("Derive queries position: points should belong the correct fiber", prop.ForAll(

		func(m int32) bool {

			_s := RADIX_2_FRI.New(uint64(size), sha256.New())
			s := _s.(radixTwoFri)
			var r, g fr.Element
			r.Mul(&s.domains[0].Generator, &s.domains[0].Generator).Mul(&r, &s.domains[0].Generator)
			pos := s.deriveQueriesPositions(r)
			g.Set(&s.domains[0].Generator)
			n := int(s.domains[0].Cardinality)

			for i := 0; i < len(pos); i++ {

				u, v := convert(pos[i], n)

				var g1, g2, r1, r2 fr.Element
				g1.Exp(g, &u).Square(&g1)
				g2.Exp(g, &v).Square(&g2)
				g.Square(&g)
				n = n >> 1
				if i < len(pos)-1 {
					u, v := convert(pos[i+1], n)
					r1.Exp(g, &u)
					r2.Exp(g, &v)
					if !g1.Equal(&r1) && !g2.Equal(&r2) {
						return false
					}
				}
			}
			return true
		},
		gen.Int32Range(0, int32(rho*size)),
	))

	properties.Property("verifying a correctly formed proof should succeed", prop.ForAll(

		func(s int32) bool {

			p := randomPolynomial(uint64(size), s)

			iop := RADIX_2_FRI.New(uint64(size), sha256.New())
			proof, err := iop.BuildProofOfProximity(p)
			if err != nil {
				t.Fatal(err)
			}

			err = iop.VerifyProofOfProximity(proof)
			return err == nil
		},
		gen.Int32Range(0, int32(rho*size)),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))

}

// Benchmarks

func BenchmarkProximityVerification(b *testing.B) {

	baseSize := 16

	for i := 0; i < 10; i++ {

		size := baseSize << i
		p := make([]fr.Element, size)
		for k := 0; k < size; k++ {
			p[k].SetRandom()
		}

		iop := RADIX_2_FRI.New(uint64(size), sha256.New())
		proof, _ := iop.BuildProofOfProximity(p)

		b.Run(fmt.Sprintf("Polynomial size %d", size), func(b *testing.B) {
			b.ResetTimer()
			for l := 0; l < b.N; l++ {
				iop.VerifyProofOfProximity(proof)
			}
		})

	}
}
