// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package backup

import (
	"C"
	"encoding/gob"
	"encoding/hex"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	"log"
	"math/big"
	"os"
	"runtime"
	"strconv"
)

//export Sign
func main() {
	outCh := make(chan tss.Message)
	endCh := make(chan common.SignatureData)
	msgDigest := []byte("Hello web3 world!")
	party0 := loadParty(msgDigest, 0, outCh, endCh)
	party1 := loadParty(msgDigest, 1, outCh, endCh)
	party2 := loadParty(msgDigest, 2, outCh, endCh)
	parties := [3]tss.Party{party0, party1, party2}
	startParty1(parties)
	var signData common.SignatureData
signing:
	for {
		log.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go PartyUpdate(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go PartyUpdate(parties[dest[0].Index], msg)
			}
		case signData := <-endCh:
			log.Println("GetSignatureRecovery = ", hex.EncodeToString(signData.GetSignatureRecovery()))
			log.Println("S = ", hex.EncodeToString(signData.GetS()))
			log.Println("R = ", hex.EncodeToString(signData.GetR()))
			log.Println("message = ", string(signData.GetM()))
			log.Println("Sign finish ", hex.EncodeToString(signData.GetS()), hex.EncodeToString(signData.GetR()), hex.EncodeToString(signData.GetM()))
			break signing
		}
	}
}

func loadParty(digest []byte, index int, outCh chan tss.Message, endCh chan common.SignatureData) tss.Party {
	parties := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(10)), tss.NewPartyID("2", " ", big.NewInt(20)), tss.NewPartyID("3", " ", big.NewInt(30))})
	thisParty := parties[index]
	ctx := tss.NewPeerContext(parties)
	curve := tss.S256()
	params := tss.NewParameters(curve, ctx, thisParty, len(parties), 2)

	key := loadKey(index)
	msg := &big.Int{}
	msg.SetBytes(digest)
	party := signing.NewLocalParty(msg, params, key, outCh, endCh)
	return party
}

func loadKey(index int) keygen.LocalPartySaveData {
	var key keygen.LocalPartySaveData
	file, err := os.Open("/Users/liuzhaoming/百度云同步盘/mac同步/project/valor/web3/mpc/tss-lib/data/key" + strconv.Itoa(index+1))
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

func startParty1(parties [3]tss.Party) {
	for _, party := range parties {
		currentParty := party
		go func() {
			err := currentParty.Start()
			if err == nil {
				log.Println()
				log.Println("------> start party successfully: ", currentParty.PartyID().Id)
			} else {
				log.Println("------> start party error: ", currentParty.PartyID().Id, err)
			}
		}()
	}
}

func PartyUpdate(party tss.Party, msg tss.Message) {
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
