// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"encoding/hex"
	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"log"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	//Generate()
	Sign()
}

// Generate GG18秘钥生成
func Generate() {
	partyIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(1)),
		tss.NewPartyID("2", " ", big.NewInt(2)), tss.NewPartyID("3", " ", big.NewInt(3))})
	p2PCtx := tss.NewPeerContext(partyIDs)
	committees := make([]*keygen.LocalParty, 0, len(partyIDs))
	outCh := make(chan tss.Message, len(partyIDs))
	endCh := make(chan *keygen.LocalPartySaveData, len(partyIDs))

	for _, pID := range partyIDs {
		preParams, _ := keygen.GeneratePreParams(time.Minute * 3)
		params := tss.NewParameters(tss.EC(), p2PCtx, pID, len(partyIDs), 1)
		party := keygen.NewLocalParty(params, outCh, endCh, *preParams).(*keygen.LocalParty)
		committees = append(committees, party)
	}

	for _, P := range committees {
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				log.Println("Start party error", err)
			}
		}(P)
	}

	saveDataArray := make([]keygen.LocalPartySaveData, len(committees))
	var keygenEnded int32
keygening:
	for {
		log.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range committees {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go partyUpdate(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go partyUpdate(committees[dest[0].Index], msg)
			}
		case saveData := <-endCh:
			log.Println("------> receive save data")
			if saveData.Xi != nil {
				index, err := saveData.OriginalIndex()
				if err != nil {
					log.Println("should not be an error getting a party's index from save data", err)
				}
				saveDataArray[index] = *saveData
			}
			atomic.AddInt32(&keygenEnded, 1)

			if atomic.LoadInt32(&keygenEnded) == int32(len(partyIDs)) {
				log.Printf("Keygen done. Reshared %d participants\n", keygenEnded)
				break keygening
			}
		}
	}

	log.Println("=========> Key generate finish")
	saveKey(saveDataArray[0], saveDataArray[1], saveDataArray[2])

	privateKey, _ := reconstruct1(2, tss.S256(), [3]keygen.LocalPartySaveData{saveDataArray[0], saveDataArray[1], saveDataArray[2]})
	log.Println("reconstruct finish", privateKey)
	log.Println(privateKey.PublicKey)
	log.Println(hex.EncodeToString(privateKey.D.Bytes()))
}

// Sign GG18签名
func Sign() {
	partyIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(1)),
		tss.NewPartyID("2", " ", big.NewInt(2))})
	p2PCtx := tss.NewPeerContext(partyIDs)
	committees := make([]*signing.LocalParty, 0, len(partyIDs))
	outCh := make(chan tss.Message, len(partyIDs))
	endCh := make(chan *common.SignatureData, len(partyIDs))
	msg := &big.Int{}
	msg.SetBytes([]byte("Hello web3 world!"))

	for i, pID := range partyIDs {
		params := tss.NewParameters(tss.EC(), p2PCtx, pID, len(partyIDs), 1)
		key := loadKey(i)
		party := signing.NewLocalParty(msg, params, key, outCh, endCh).(*signing.LocalParty)
		committees = append(committees, party)
	}

	for _, P := range committees {
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				log.Println("Start party error", err)
			}
		}(P)
	}

	var signEnded int32
signing:
	for {
		log.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range committees {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go partyUpdate(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go partyUpdate(committees[dest[0].Index], msg)
			}
		case signData := <-endCh:
			log.Println("GetSignatureRecovery = ", hex.EncodeToString(signData.GetSignatureRecovery()))
			log.Println("S = ", hex.EncodeToString(signData.GetS()))
			log.Println("R = ", hex.EncodeToString(signData.GetR()))
			log.Println("message = ", string(signData.GetM()))
			log.Println("Sign finish ", hex.EncodeToString(signData.GetS()), hex.EncodeToString(signData.GetR()), hex.EncodeToString(signData.GetM()))

			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(partyIDs)) {
				log.Printf("Sign done. Reshared %d participants\n", signEnded)
				break signing
			}
		}
	}
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

func saveKey(data0 keygen.LocalPartySaveData, data1 keygen.LocalPartySaveData, data2 keygen.LocalPartySaveData) {
	doSaveKey(1, data0)
	doSaveKey(2, data1)
	doSaveKey(3, data2)
}

func doSaveKey(index int, data keygen.LocalPartySaveData) {
	file, err := os.Create("data/gg18-key" + strconv.Itoa(index))
	if err != nil {
		log.Println("Cannot create file ", err)
		return
	}

	enc := gob.NewEncoder(file)
	err2 := enc.Encode(data)
	if err2 != nil {
		log.Println("Cannot write file ", err)
		return
	}
}

func reconstruct1(threshold int, ec elliptic.Curve, shares [3]keygen.LocalPartySaveData) (*ecdsa.PrivateKey, error) {
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

func loadKey(index int) keygen.LocalPartySaveData {
	var key keygen.LocalPartySaveData
	file, err := os.Open("/Users/liuzhaoming/百度云同步盘/mac同步/project/valor/web3/mpc/tss-lib/data/gg18-key" + strconv.Itoa(index+1))
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
