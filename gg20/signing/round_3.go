// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/mta"
	"github.com/bnb-chain/tss-lib/v2/crypto/zkp"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	alphas := make([]*big.Int, len(round.Parties().IDs()))
	us := make([]*big.Int, len(round.Parties().IDs()))

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ContextJ := append(round.temp.ssid, new(big.Int).SetUint64(uint64(j)).Bytes()...)
		// Alice_end
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBob, err := r2msg.UnmarshalProofBob()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBob failed"), Pj)
				return
			}
			alphaIJ, err := mta.AliceEnd(
				ContextJ,
				round.Params().EC(),
				round.key.PaillierPKs[i],
				proofBob,
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.cis[j],
				new(big.Int).SetBytes(r2msg.GetC1()),
				round.key.NTildej[i],
				round.key.PaillierSK)
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			alphas[j] = alphaIJ
			round.temp.r5AbortData.AlphaIJ[j] = alphaIJ.Bytes()
		}(j, Pj)
		// Alice_end_wc
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBobWC, err := r2msg.UnmarshalProofBobWC(round.Parameters.EC())
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBobWC failed"), Pj)
				return
			}
			uIj, err := mta.AliceEndWC(
				ContextJ,
				round.Params().EC(),
				round.key.PaillierPKs[i],
				proofBobWC,
				round.temp.bigWs[j],
				round.temp.cis[j],
				new(big.Int).SetBytes(r2msg.GetC2()),
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.key.PaillierSK)
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			us[j] = uIj
		}(j, Pj)
	}

	// consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Alice_end or Alice_end_wc"), culprits...)
	}

	q := round.Params().EC().Params().N
	modN := common.ModInt(q)

	kI := new(big.Int).SetBytes(round.temp.KI)
	deltaI := modN.Mul(kI, round.temp.gammaI)
	sigmaI := modN.Mul(kI, round.temp.wI)

	// clear wI from temp memory
	round.temp.wI = zero

	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		deltaI = modN.Add(deltaI, alphas[j].Add(alphas[j], round.temp.betas[j]))
		sigmaI = modN.Add(sigmaI, us[j].Add(us[j], round.temp.vs[j]))
	}

	// gg20: calculate T_i = g^sigma_i h^l_i
	lI := common.GetRandomPositiveInt(round.Rand(), q)
	h, err := crypto.ECBasePoint2(round.Params().EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	hLI := h.ScalarMult(lI)
	gSigmaI := crypto.ScalarBaseMult(round.Params().EC(), sigmaI)
	TI, err := gSigmaI.Add(hLI)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// gg20: generate the ZK proof of T_i, verified in ValidateBasic for the round 3 message
	tProof, err := zkp.NewTProof(round.Params().EC(), TI, h, sigmaI, lI, round.Rand())
	if err != nil {
		return round.WrapError(err, Pi)
	}

	round.temp.TI = TI
	round.temp.lI = lI
	round.temp.deltaI = deltaI
	round.temp.sigmaI = sigmaI

	r3msg := NewSignRound3Message(Pi, deltaI, TI, tProof)
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
