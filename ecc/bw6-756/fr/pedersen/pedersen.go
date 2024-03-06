// Copyright 2020 Consensys Software Inc.
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

package pedersen

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bw6-756"
	"github.com/consensys/gnark-crypto/ecc/bw6-756/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"io"
	"math/big"
)

// ProvingKey for committing and proofs of knowledge
type ProvingKey struct {
	basis         []curve.G1Affine
	basisExpSigma []curve.G1Affine
}

type VerifyingKey struct {
	G             curve.G2Affine // TODO @tabaie: does this really have to be randomized?
	GRootSigmaNeg curve.G2Affine //gRootSigmaNeg = g^{-1/σ}
}

func randomFrSizedBytes() ([]byte, error) {
	res := make([]byte, fr.Bytes)
	_, err := rand.Read(res)
	return res, err
}

func randomOnG2() (curve.G2Affine, error) { // TODO: Add to G2.go?
	if gBytes, err := randomFrSizedBytes(); err != nil {
		return curve.G2Affine{}, err
	} else {
		return curve.HashToG2(gBytes, []byte("random on g2"))
	}
}

func Setup(bases ...[]curve.G1Affine) (pk []ProvingKey, vk VerifyingKey, err error) {

	if vk.G, err = randomOnG2(); err != nil {
		return
	}

	var modMinusOne big.Int
	modMinusOne.Sub(fr.Modulus(), big.NewInt(1))
	var sigma *big.Int
	if sigma, err = rand.Int(rand.Reader, &modMinusOne); err != nil {
		return
	}
	sigma.Add(sigma, big.NewInt(1))

	var sigmaInvNeg big.Int
	sigmaInvNeg.ModInverse(sigma, fr.Modulus())
	sigmaInvNeg.Sub(fr.Modulus(), &sigmaInvNeg)
	vk.GRootSigmaNeg.ScalarMultiplication(&vk.G, &sigmaInvNeg)

	pk = make([]ProvingKey, len(bases))
	for i := range bases {
		pk[i].basisExpSigma = make([]curve.G1Affine, len(bases[i]))
		for j := range bases[i] {
			pk[i].basisExpSigma[j].ScalarMultiplication(&bases[i][j], sigma)
		}
		pk[i].basis = bases[i]
	}
	return
}

func (pk *ProvingKey) ProveKnowledge(values []fr.Element) (pok curve.G1Affine, err error) {
	if len(values) != len(pk.basis) {
		err = fmt.Errorf("must have as many values as basis elements")
		return
	}

	// TODO @gbotrel this will spawn more than one task, see
	// https://github.com/ConsenSys/gnark-crypto/issues/269
	config := ecc.MultiExpConfig{
		NbTasks: 1, // TODO Experiment
	}

	_, err = pok.MultiExp(pk.basisExpSigma, values, config)
	return
}

func (pk *ProvingKey) Commit(values []fr.Element) (commitment curve.G1Affine, err error) {

	if len(values) != len(pk.basis) {
		err = fmt.Errorf("must have as many values as basis elements")
		return
	}

	// TODO @gbotrel this will spawn more than one task, see
	// https://github.com/ConsenSys/gnark-crypto/issues/269
	config := ecc.MultiExpConfig{
		NbTasks: 1,
	}
	_, err = commitment.MultiExp(pk.basis, values, config)

	return
}

// BatchProve generates a single proof of knowledge for multiple commitments for faster verification
func BatchProve(pk []ProvingKey, values [][]fr.Element, fiatshamirSeeds ...[]byte) (pok curve.G1Affine, err error) {
	if len(pk) != len(values) {
		err = fmt.Errorf("must have as many value vectors as bases")
		return
	}

	if len(pk) == 1 { // no need to fold
		return pk[0].ProveKnowledge(values[0])
	} else if len(pk) == 0 { // nothing to do at all
		return
	}

	offset := 0
	for i := range pk {
		if len(values[i]) != len(pk[i].basis) {
			err = fmt.Errorf("must have as many values as basis elements")
			return
		}
		offset += len(values[i])
	}

	var r fr.Element
	if r, err = getChallenge(fiatshamirSeeds); err != nil {
		return
	}

	// prepare one amalgamated MSM
	scaledValues := make([]fr.Element, offset)
	basis := make([]curve.G1Affine, offset)

	copy(basis, pk[0].basisExpSigma)
	copy(scaledValues, values[0])

	offset = len(values[0])
	rI := r
	for i := 1; i < len(pk); i++ {
		copy(basis[offset:], pk[i].basisExpSigma)
		for j := range pk[i].basis {
			scaledValues[offset].Mul(&values[i][j], &rI)
			offset++
		}
		if i+1 < len(pk) {
			rI.Mul(&rI, &r)
		}
	}

	// TODO @gbotrel this will spawn more than one task, see
	// https://github.com/ConsenSys/gnark-crypto/issues/269
	config := ecc.MultiExpConfig{
		NbTasks: 1,
	}

	_, err = pok.MultiExp(basis, scaledValues, config)
	return
}

// FoldCommitments amalgamates multiple commitments into one, which can be verifier against a folded proof obtained from BatchProve
func FoldCommitments(commitments []curve.G1Affine, fiatshamirSeeds ...[]byte) (commitment curve.G1Affine, err error) {

	if len(commitments) == 1 { // no need to fold
		commitment = commitments[0]
		return
	} else if len(commitments) == 0 { // nothing to do at all
		return
	}

	r := make([]fr.Element, len(commitments))
	r[0].SetOne()
	if r[1], err = getChallenge(fiatshamirSeeds); err != nil {
		return
	}
	for i := 2; i < len(commitments); i++ {
		r[i].Mul(&r[i-1], &r[1])
	}

	for i := range commitments { // TODO @Tabaie Remove if MSM does subgroup check for you
		if !commitments[i].IsInSubGroup() {
			err = fmt.Errorf("subgroup check failed")
			return
		}
	}

	// TODO @gbotrel this will spawn more than one task, see
	// https://github.com/ConsenSys/gnark-crypto/issues/269
	config := ecc.MultiExpConfig{
		NbTasks: 1,
	}
	_, err = commitment.MultiExp(commitments, r, config)
	return
}

// Verify checks if the proof of knowledge is valid
func (vk *VerifyingKey) Verify(commitment curve.G1Affine, knowledgeProof curve.G1Affine) error {

	if !commitment.IsInSubGroup() || !knowledgeProof.IsInSubGroup() {
		return fmt.Errorf("subgroup check failed")
	}

	if isOne, err := curve.PairingCheck([]curve.G1Affine{commitment, knowledgeProof}, []curve.G2Affine{vk.G, vk.GRootSigmaNeg}); err != nil {
		return err
	} else if !isOne {
		return fmt.Errorf("proof rejected")
	}
	return nil
}

func getChallenge(fiatshamirSeeds [][]byte) (r fr.Element, err error) {
	// incorporate user-provided seeds into the transcript
	t := fiatshamir.NewTranscript(sha256.New(), "r")
	for i := range fiatshamirSeeds {
		if err = t.Bind("r", fiatshamirSeeds[i]); err != nil {
			return
		}
	}

	// obtain the challenge
	var rBytes []byte

	if rBytes, err = t.ComputeChallenge("r"); err != nil {
		return
	}
	r.SetBytes(rBytes) // TODO @Tabaie Plonk challenge generation done the same way; replace both with hash to fr?
	return
}

// Marshal

func (pk *ProvingKey) writeTo(enc *curve.Encoder) (int64, error) {
	if err := enc.Encode(pk.basis); err != nil {
		return enc.BytesWritten(), err
	}

	err := enc.Encode(pk.basisExpSigma)

	return enc.BytesWritten(), err
}

func (pk *ProvingKey) WriteTo(w io.Writer) (int64, error) {
	return pk.writeTo(curve.NewEncoder(w))
}

func (pk *ProvingKey) WriteRawTo(w io.Writer) (int64, error) {
	return pk.writeTo(curve.NewEncoder(w, curve.RawEncoding()))
}

func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {
	dec := curve.NewDecoder(r)

	if err := dec.Decode(&pk.basis); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&pk.basisExpSigma); err != nil {
		return dec.BytesRead(), err
	}

	if cL, pL := len(pk.basis), len(pk.basisExpSigma); cL != pL {
		return dec.BytesRead(), fmt.Errorf("commitment basis size (%d) doesn't match proof basis size (%d)", cL, pL)
	}

	return dec.BytesRead(), nil
}

func (vk *VerifyingKey) WriteTo(w io.Writer) (int64, error) {
	return vk.writeTo(curve.NewEncoder(w))
}

func (vk *VerifyingKey) WriteRawTo(w io.Writer) (int64, error) {
	return vk.writeTo(curve.NewEncoder(w, curve.RawEncoding()))
}

func (vk *VerifyingKey) writeTo(enc *curve.Encoder) (int64, error) {
	var err error

	if err = enc.Encode(&vk.G); err != nil {
		return enc.BytesWritten(), err
	}
	err = enc.Encode(&vk.GRootSigmaNeg)
	return enc.BytesWritten(), err
}

func (vk *VerifyingKey) ReadFrom(r io.Reader) (int64, error) {
	return vk.readFrom(r)
}

func (vk *VerifyingKey) UnsafeReadFrom(r io.Reader) (int64, error) {
	return vk.readFrom(r, curve.NoSubgroupChecks())
}

func (vk *VerifyingKey) readFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)
	var err error

	if err = dec.Decode(&vk.G); err != nil {
		return dec.BytesRead(), err
	}
	err = dec.Decode(&vk.GRootSigmaNeg)
	return dec.BytesRead(), err
}
