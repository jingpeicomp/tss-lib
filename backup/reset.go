// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package backup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/tss"
	"log"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
)

func main3() {
	oldPartyIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(1)),
		tss.NewPartyID("2", " ", big.NewInt(2)), tss.NewPartyID("3", " ", big.NewInt(3))})
	oldP2PCtx := tss.NewPeerContext(oldPartyIDs)
	newPartyIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(10)),
		tss.NewPartyID("2", " ", big.NewInt(20)), tss.NewPartyID("3", " ", big.NewInt(30))})
	newP2PCtx := tss.NewPeerContext(newPartyIDs)
	oldCommittee := make([]*resharing.LocalParty, 0, len(oldPartyIDs))
	newCommittee := make([]*resharing.LocalParty, 0, len(newPartyIDs))
	bothCommitteesPax := len(oldPartyIDs) + len(newPartyIDs)

	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan keygen.LocalPartySaveData, bothCommitteesPax)
	for j, pID := range oldPartyIDs {
		key := loadKeyReset(j)
		params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, 3, 2, 3, 2)
		P := resharing.NewLocalParty(params, key, outCh, endCh).(*resharing.LocalParty)
		oldCommittee = append(oldCommittee, P)
	}
	// init the new parties
	for _, pID := range newPartyIDs {
		params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, 3, 2, 3, 2)
		saveData := keygen.NewLocalPartySaveData(len(newPartyIDs))
		P := resharing.NewLocalParty(params, saveData, outCh, endCh).(*resharing.LocalParty)
		newCommittee = append(newCommittee, P)
	}

	for _, P := range oldCommittee {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				log.Println("Start old party error", err)
			}
		}(P)
	}
	for _, P := range newCommittee {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				log.Println("Start new party error", err)
			}
		}(P)
	}

	saveDataArray := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
resetting:
	for {
		log.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				log.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destItem := range dest[:len(oldCommittee)] {
					go partyUpdate(oldCommittee[destItem.Index], msg)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destItem := range dest {
					go partyUpdate(newCommittee[destItem.Index], msg)
				}
			}
		case saveData := <-endCh:
			log.Println("------> receive save data")
			if saveData.Xi != nil {
				index, err := saveData.OriginalIndex()
				if err != nil {
					log.Println("should not be an error getting a party's index from save data", err)
				}
				saveDataArray[index] = saveData
			} else {
				endedOldCommittee++
			}
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(bothCommitteesPax) {
				if len(oldCommittee) != endedOldCommittee {
					log.Printf("Resharing done. Reshared %d participants\n", reSharingEnded)
				}
				// more verification of signing is implemented within local_party_test.go of keygen package
				break resetting
			}
		}
	}

	for i, value := range saveDataArray {
		doSaveKey(i+1, value)
	}
	privateKey, _ := reconstructReset(2, tss.S256(), saveDataArray)
	log.Println("========> reconstruct finish", privateKey)
}

func loadKeyReset(index int) keygen.LocalPartySaveData {
	var key keygen.LocalPartySaveData
	file, err := os.Open("data/key" + strconv.Itoa(index+1))
	if err != nil {
		log.Println("Cannot create file ", err)
		return key
	}

	dec := gob.NewDecoder(file)
	err2 := dec.Decode(&key)
	if err2 != nil {
		log.Println("Cannot write file ", err)
	}
	return key
}

func reconstructReset(threshold int, ec elliptic.Curve, shares []keygen.LocalPartySaveData) (*ecdsa.PrivateKey, error) {
	var vssShares = make(vss.Shares, len(shares))
	for i, share := range shares {
		vssShare := &vss.Share{
			Threshold: threshold,
			ID:        share.ShareID,
			Share:     share.Xi,
		}
		vssShares[i] = vssShare
	}

	d, err := vssShares.ReConstruct(ec)
	if err != nil {
		return nil, err
	}

	x, y := ec.ScalarBaseMult(d.Bytes())

	privateKey := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: ec,
			X:     x,
			Y:     y,
		},
	}

	return privateKey, nil
}

func partyUpdate(party tss.Party, msg tss.Message) {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		log.Println("Message error", err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		log.Println("Pare Message error", err)
		return
	}
	if _, err := party.Update(pMsg); err != nil {
		log.Println("Update Message error", err)
	}
}
