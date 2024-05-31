// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	cmt "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/mta"
	"github.com/bnb-chain/tss-lib/v2/crypto/zkp"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
		(*SignRound4Message)(nil),
		(*SignRound5Message)(nil),
		(*SignRound6Message)(nil),
		(*SignRound7Message)(nil),
	}
)

// ----- //

func NewSignRound1Message1(
	to, from *tss.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := proof.Bytes()
	content := &SignRound1Message1{
		C:               c.Bytes(),
		RangeProofAlice: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC()) &&
		common.NonEmptyMultiBytes(m.GetRangeProofAlice(), mta.RangeProofAliceBytesParts)
}

func (m *SignRound1Message1) UnmarshalC() *big.Int {
	return new(big.Int).SetBytes(m.GetC())
}

func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*mta.RangeProofAlice, error) {
	return mta.RangeProofAliceFromBytes(m.GetRangeProofAlice())
}

// ----- //

func NewSignRound1Message2(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message2) ValidateBasic() bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *SignRound1Message2) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound2Message(
	to, from *tss.PartyID,
	c1Ji *big.Int,
	pi1Ji *mta.ProofBob,
	c2Ji *big.Int,
	pi2Ji *mta.ProofBobWC,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBob := pi1Ji.Bytes()
	pfBobWC := pi2Ji.Bytes()
	content := &SignRound2Message{
		C1:         c1Ji.Bytes(),
		C2:         c2Ji.Bytes(),
		ProofBob:   pfBob[:],
		ProofBobWc: pfBobWC[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC1()) &&
		common.NonEmptyBytes(m.GetC2()) &&
		common.NonEmptyMultiBytes(m.GetProofBob(), mta.ProofBobBytesParts) &&
		common.NonEmptyMultiBytes(m.GetProofBobWc(), mta.ProofBobWCBytesParts)
}

func (m *SignRound2Message) UnmarshalProofBob() (*mta.ProofBob, error) {
	return mta.ProofBobFromBytes(m.GetProofBob())
}

func (m *SignRound2Message) UnmarshalProofBobWC(ec elliptic.Curve) (*mta.ProofBobWC, error) {
	return mta.ProofBobWCFromBytes(ec, m.GetProofBobWc())
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	deltaI *big.Int,
	TI *crypto.ECPoint,
	tProof *zkp.TProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		DeltaI:       deltaI.Bytes(),
		TIX:          TI.X().Bytes(),
		TIY:          TI.Y().Bytes(),
		TProofAlphaX: tProof.Alpha.X().Bytes(),
		TProofAlphaY: tProof.Alpha.Y().Bytes(),
		TProofT:      tProof.T.Bytes(),
		TProofU:      tProof.U.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	if m == nil ||
		!common.NonEmptyBytes(m.GetDeltaI()) ||
		!common.NonEmptyBytes(m.GetTIX()) ||
		!common.NonEmptyBytes(m.GetTIY()) ||
		!common.NonEmptyBytes(m.GetTProofAlphaX()) ||
		!common.NonEmptyBytes(m.GetTProofAlphaY()) ||
		!common.NonEmptyBytes(m.GetTProofT()) ||
		!common.NonEmptyBytes(m.GetTProofU()) {
		return false
	}

	// Todo
	// The curve should be obtained from the method input parameters,
	// but this method is an interface method and cannot add input parameters.
	ec := tss.EC()
	TI, err := m.UnmarshalTI(ec)
	if err != nil {
		return false
	}
	tProof, err := m.UnmarshalTProof(ec)
	if err != nil {
		return false
	}
	// we have everything we need to validate the TProof here!
	basePoint2, err := crypto.ECBasePoint2(ec)
	if err != nil {
		return false
	}
	return TI.ValidateBasic() && tProof.Verify(ec, TI, basePoint2)
}

func (m *SignRound3Message) UnmarshalTI(ec elliptic.Curve) (*crypto.ECPoint, error) {
	if m.GetTIX() == nil || m.GetTIY() == nil {
		return nil, errors.New("UnmarshalTI() X or Y coord is nil")
	}
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetTIX()),
		new(big.Int).SetBytes(m.GetTIY()))
}

func (m *SignRound3Message) UnmarshalTProof(ec elliptic.Curve) (*zkp.TProof, error) {
	alpha, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetTProofAlphaX()),
		new(big.Int).SetBytes(m.GetTProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &zkp.TProof{
		Alpha: alpha,
		T:     new(big.Int).SetBytes(m.GetTProofT()),
		U:     new(big.Int).SetBytes(m.GetTProofU()),
	}, nil
}

// ----- //

func NewSignRound4Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound4Message{
		DeCommitment: dcBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3)
}

func (m *SignRound4Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewSignRound5Message(
	from *tss.PartyID,
	Ri *crypto.ECPoint,
	pdlwSlackPf *zkp.PDLwSlackProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs, err := pdlwSlackPf.Marshal()
	if err != nil {
		return nil
	}
	content := &SignRound5Message{
		RIX:            Ri.X().Bytes(),
		RIY:            Ri.Y().Bytes(),
		ProofPdlWSlack: pfBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound5Message) ValidateBasic() bool {
	if m == nil ||
		!common.NonEmptyBytes(m.GetRIX()) ||
		!common.NonEmptyBytes(m.GetRIY()) ||
		!common.NonEmptyMultiBytes(m.GetProofPdlWSlack(), zkp.PDLwSlackMarshalledParts) {
		return false
	}
	// Todo
	// The curve should be obtained from the method input parameters,
	// but this method is an interface method and cannot add input parameters.
	ec := tss.EC()
	RI, err := m.UnmarshalRI(ec)
	if err != nil {
		return false
	}
	return RI.ValidateBasic()
}

func (m *SignRound5Message) UnmarshalRI(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(ec,
		new(big.Int).SetBytes(m.GetRIX()),
		new(big.Int).SetBytes(m.GetRIY()))
}

func (m *SignRound5Message) UnmarshalPDLwSlackProof() (*zkp.PDLwSlackProof, error) {
	return zkp.UnmarshalPDLwSlackProof(m.GetProofPdlWSlack())
}

// ----- //

func NewSignRound6MessageSuccess(
	from *tss.PartyID,
	sI *crypto.ECPoint,
	proof *zkp.STProof,

) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound6Message{
		Content: &SignRound6Message_Success{
			Success: &SignRound6Message_SuccessData{
				SIX:           sI.X().Bytes(),
				SIY:           sI.Y().Bytes(),
				StProofAlphaX: proof.Alpha.X().Bytes(),
				StProofAlphaY: proof.Alpha.Y().Bytes(),
				StProofBetaX:  proof.Beta.X().Bytes(),
				StProofBetaY:  proof.Beta.Y().Bytes(),
				StProofT:      proof.T.Bytes(),
				StProofU:      proof.U.Bytes(),
			},
		},
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func NewSignRound6MessageAbort(
	from *tss.PartyID,
	data *SignRound6Message_AbortData,

) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound6Message{
		Content: &SignRound6Message_Abort{
			Abort: data,
		},
	}
	// this hack makes the ValidateBasic pass because the [i] index position is empty in these arrays
	data.GetAlphaIJ()[from.Index] = []byte{1}
	data.GetBetaJI()[from.Index] = []byte{1}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound6Message) ValidateBasic() bool {
	if m == nil {
		return false
	}
	switch c := m.GetContent().(type) {
	case *SignRound6Message_Success:
		if !common.NonEmptyBytes(c.Success.GetSIX()) ||
			!common.NonEmptyBytes(c.Success.GetSIY()) ||
			!common.NonEmptyBytes(c.Success.GetStProofAlphaX()) ||
			!common.NonEmptyBytes(c.Success.GetStProofAlphaY()) ||
			!common.NonEmptyBytes(c.Success.GetStProofBetaX()) ||
			!common.NonEmptyBytes(c.Success.GetStProofBetaY()) ||
			!common.NonEmptyBytes(c.Success.GetStProofT()) ||
			!common.NonEmptyBytes(c.Success.GetStProofU()) {
			return false
		}

		// Todo
		// The curve should be obtained from the method input parameters,
		// but this method is an interface method and cannot add input parameters.
		ec := tss.EC()
		sI, err := c.Success.UnmarshalSI(ec)
		if err != nil {
			return false
		}

		tProof, err := c.Success.UnmarshalSTProof(ec)
		if err != nil {
			return false
		}
		return sI.ValidateBasic() && tProof.ValidateBasic()
	case *SignRound6Message_Abort:
		return common.NonEmptyBytes(c.Abort.GetKI()) &&
			common.NonEmptyBytes(c.Abort.GetKIRandomness()) &&
			common.NonEmptyBytes(c.Abort.GetGammaI()) &&
			common.NonEmptyMultiBytes(c.Abort.GetAlphaIJ()) &&
			common.NonEmptyMultiBytes(c.Abort.GetBetaJI()) &&
			len(c.Abort.GetAlphaIJ()) == len(c.Abort.GetBetaJI())
	default:
		return false
	}
}

func (m *SignRound6Message_SuccessData) UnmarshalSI(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(ec,
		new(big.Int).SetBytes(m.GetSIX()),
		new(big.Int).SetBytes(m.GetSIY()))
}

func (m *SignRound6Message_SuccessData) UnmarshalSTProof(ec elliptic.Curve) (*zkp.STProof, error) {
	alpha, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetStProofAlphaX()),
		new(big.Int).SetBytes(m.GetStProofAlphaY()))
	if err != nil {
		return nil, err
	}
	beta, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetStProofBetaX()),
		new(big.Int).SetBytes(m.GetStProofBetaY()))
	if err != nil {
		return nil, err
	}
	return &zkp.STProof{
		Alpha: alpha,
		Beta:  beta,
		T:     new(big.Int).SetBytes(m.GetStProofT()),
		U:     new(big.Int).SetBytes(m.GetStProofU()),
	}, nil
}

// ----- //

func NewSignRound7Message(
	from *tss.PartyID,
	sI *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound7Message{
		SI: sI.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound7Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SI)
}
