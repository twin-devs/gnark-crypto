package dfri

import (
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"hash"
)

func DistributedFRI() {
	input := make(map[int][]fr.Element)     // map[index]polynomial_in_coefficient_form
	codewords := make(map[int][]fr.Element) // map[index]codeword
	num_polys := len(input)

	for i := 0; i < num_polys; i++ {
		// Generate ith codeword
		codewords[i] = []fr.Element{}
	}

	masterPolynomial := aggregate(codewords)

	// sort q to have fibers in contiguous entries. The goal is to have one
	// Merkle path for both openings of entries which are in the same fiber.
	q := sort(masterPolynomial)

	// build the Merkle proof, we the position is converted to fit the sorted polynomial
	pos := convertCanonicalSorted(0, len(q))
	var h hash.Hash
	tree := merkletree.New(h)
	err := tree.SetIndex(uint64(pos))
	if err != nil {
		fmt.Println(err)
		return
	}

	for i := 0; i < len(q); i++ {
		tree.Push(q[i].Marshal())
	}

	merkleRoot, proofSet, proofIndex, numLeaves := tree.Prove()
	fmt.Println(merkleRoot, proofSet, proofIndex, numLeaves)
}

func aggregate(m map[int][]fr.Element) []fr.Element {
	var aggPoly []fr.Element
	for _, poly := range m {
		for i := 0; i < len(poly); i++ {
			aggPoly[i] = poly[i] // Refactor this
		}
	}

	return aggPoly
}

// sort orders the evaluation of a polynomial on a domain
// such that contiguous entries are in the same fiber:
// {q(g⁰), q(g^{n/2}), q(g¹), q(g^{1+n/2}),...,q(g^{n/2-1}), q(gⁿ⁻¹)}
// Taken from ecc/bn254/fri/fri.go
func sort(evaluations []fr.Element) []fr.Element {
	q := make([]fr.Element, len(evaluations))
	n := len(evaluations) / 2
	for i := 0; i < n; i++ {
		q[2*i].Set(&evaluations[i])
		q[2*i+1].Set(&evaluations[i+n])
	}
	return q
}

// convertCanonicalSorted convert the index i, an entry in a
// sorted polynomial, to the corresponding entry in canonical
// representation. n is the size of the polynomial.
// Taken from ecc/bn254/fri/fri.go
func convertCanonicalSorted(i, n int) int {
	if i < n/2 {
		return 2 * i
	} else {
		l := n - (i + 1)
		l = 2 * l
		return n - l - 1
	}
}
