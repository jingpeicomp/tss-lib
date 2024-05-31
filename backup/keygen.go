// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package backup

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"
)

func main11() {
	iterSize := 10000
	startTime := time.Now().UnixMilli()
	for i := 1; i <= iterSize; i++ {
		runGenUnsafePrime()
	}
	log.Println("=========> Generate prime num ", iterSize, " spends ms ", time.Now().UnixMilli()-startTime)
}

var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

func probablyPrime(prime *big.Int) bool {
	return prime != nil && prime.ProbablyPrime(30)
}
func runGenUnsafePrime() {
	pBitLen := 1024
	qBitLen := pBitLen - 1
	b := uint(qBitLen % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (qBitLen+7)/8)
	q := new(big.Int)
	p := new(big.Int)

	bigMod := new(big.Int)

	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		log.Fatal("failed to read random bytes:", err)
		return
	}

	// Clear bits in the first byte to make sure the candidate has
	// a size <= bits.
	bytes[0] &= uint8(int(1<<b) - 1)
	// Don't let the value be too small, i.e, set the most
	// significant two bits.
	// Setting the top two bits, rather than just the top bit,
	// means that when two of these values are multiplied together,
	// the result isn't ever one bit short.
	if b >= 2 {
		bytes[0] |= 3 << (b - 2)
	} else {
		// Here b==1, because b cannot be zero.
		bytes[0] |= 1
		if len(bytes) > 1 {
			bytes[1] |= 0x80
		}
	}
	// Make the value odd since an even number this large certainly
	// isn't prime.
	bytes[len(bytes)-1] |= 1

	q.SetBytes(bytes)

	// Calculate the value mod the product of smallPrimes. If it's
	// a multiple of any of these primes we add two until it isn't.
	// The probability of overflowing is minimal and can be ignored
	// because we still perform Miller-Rabin tests on the result.
	bigMod.Mod(q, smallPrimesProduct)
	mod := bigMod.Uint64()

NextDelta:
	for delta := uint64(0); delta < 1<<20; delta += 2 {
		m := mod + delta
		for _, prime := range smallPrimes {
			if m%uint64(prime) == 0 && (qBitLen > 6 || m != uint64(prime)) {
				continue NextDelta
			}
		}

		if delta > 0 {
			bigMod.SetUint64(delta)
			q.Add(q, bigMod)
		}

		break
	}

	// There is a tiny possibility that, by adding delta, we caused
	// the number to be one bit too long. Thus we check BitLen
	// here.
	if q.ProbablyPrime(20) && q.BitLen() == qBitLen {
		if probablyPrime(q) {
			p.Mul(q, big.NewInt(2))
			p.Add(p, big.NewInt(1))

			for delta := uint64(0); delta < 1<<20; delta += 2 {
				bigMod.SetUint64(delta)
				p.Add(p, bigMod)

				if probablyPrime(p) {
					break
				}
			}

			//log.Println("---------> find prime ", q, p)
			return
		}
		q = new(big.Int)
		p = new(big.Int)
	}
}

func main() {
	outChs := [3]chan tss.Message{make(chan tss.Message), make(chan tss.Message), make(chan tss.Message)}
	endChs := [3]chan keygen.LocalPartySaveData{make(chan keygen.LocalPartySaveData), make(chan keygen.LocalPartySaveData), make(chan keygen.LocalPartySaveData)}

	party0 := buildParty(0, outChs, endChs, false)
	party1 := buildParty(1, outChs, endChs, true)
	party2 := buildParty(2, outChs, endChs, true)
	parties := [3]tss.Party{party0, party1, party2}

	var wg sync.WaitGroup
	startParty(parties, wg)
	round1Msg0, round1Msg1, round1Msg2 := <-outChs[0], <-outChs[1], <-outChs[2]
	wg.Wait()
	log.Println("------> Round 1 finish")
	updateMsgSyn([3]tss.Message{round1Msg0, round1Msg1, round1Msg2}, parties, wg)

	//updateMsg(0, round1Msg0, parties, wg)
	//updateMsg(1, round1Msg1, parties, wg)
	//updateMsg(2, round1Msg2, parties, wg)
	round2ShareIjMsg0, round2ShareIjMsg1, round2ShareIjMsg2 := <-outChs[0], <-outChs[1], <-outChs[2]
	wg.Wait()
	log.Println("------> Round 2 share ij to Pj finish")
	updateMsgSyn([3]tss.Message{round2ShareIjMsg0, round2ShareIjMsg1, round2ShareIjMsg2}, parties, wg)
	//updateMsg(0, round2ShareIjMsg0, parties, wg)
	//updateMsg(1, round2ShareIjMsg1, parties, wg)
	//updateMsg(2, round2ShareIjMsg2, parties, wg)
	round2Msg0, round2Msg1, round2Msg2 := <-outChs[0], <-outChs[1], <-outChs[2]
	wg.Wait()
	log.Println("------> Round 2。。。 finish")

	updateMsgSyn([3]tss.Message{round2Msg0, round2Msg1, round2Msg2}, parties, wg)
	//updateMsg(0, round2Msg0, parties, wg)
	//updateMsg(1, round2Msg1, parties, wg)
	//updateMsg(2, round2Msg2, parties, wg)

	round21msg0, round21msg1, round21msg2 := <-outChs[0], <-outChs[1], <-outChs[2]
	wg.Wait()
	log.Println("------> Round 2 finish")

	updateMsgSyn([3]tss.Message{round21msg0, round21msg1, round21msg2}, parties, wg)
	//updateMsg(0, round3Msg0, parties, wg)
	//updateMsg(1, round3Msg1, parties, wg)
	//updateMsg(2, round3Msg2, parties, wg)

	round3Msg0, round3Msg1, round3Msg2 := <-outChs[0], <-outChs[1], <-outChs[2]
	wg.Wait()
	log.Println("------> Round 3 finish")
	updateMsgSyn([3]tss.Message{round3Msg0, round3Msg1, round3Msg2}, parties, wg)

	data0, data1, data2 := <-endChs[0], <-endChs[1], <-endChs[2]
	wg.Wait()
	log.Println("=========> Key generate finish")
	saveKey(data0, data1, data2)

	privateKey, _ := reconstruct1(2, tss.S256(), [3]keygen.LocalPartySaveData{data0, data1, data2})
	log.Println("reconstruct finish", privateKey)
	log.Println(privateKey.PublicKey)
	log.Println(hex.EncodeToString(privateKey.D.Bytes()))

	time.Sleep(time.Minute)
}

func buildParty(index int, outChs [3]chan tss.Message, endChs [3]chan keygen.LocalPartySaveData, isSafe bool) tss.Party {
	preParams, _ := keygen.GenerateOptionPreParams(3*time.Minute, isSafe)
	parties := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(1)), tss.NewPartyID("2", " ", big.NewInt(2)), tss.NewPartyID("3", " ", big.NewInt(3))})
	thisParty := parties[index]
	ctx := tss.NewPeerContext(parties)
	curve := tss.S256()
	params := tss.NewParameters(curve, ctx, thisParty, len(parties), 1)

	party := keygen.NewLocalParty(params, outChs[index], endChs[index], *preParams) // Omit the last arg to compute the pre-params in round 1
	return party
}

func startParty(parties [3]tss.Party, wg sync.WaitGroup) {
	for _, party := range parties {
		currentParty := party
		wg.Add(1)
		go func() {
			err := currentParty.Start()
			if err == nil {
				log.Println()
				log.Println("------> start party successfully: ", currentParty.PartyID().Id)
			} else {
				log.Println("------> start party error: ", currentParty.PartyID().Id, err)
			}
			defer wg.Done()
		}()
	}
}

func updateMsg(index int, msg tss.Message, parties [3]tss.Party, wg sync.WaitGroup) {
	if msg.IsBroadcast() {
		for i, party := range parties {
			if i != index {
				currentI := i
				wg.Add(1)
				go func() {
					isSuccess, errMsg := party.Update(msg.(tss.ParsedMessage))
					if !isSuccess {
						log.Println("-------> party update broadcast msg error", index, currentI, errMsg)
					} else {
						log.Println("-------> party update broadcast msg successfully", index, currentI)
					}
					wg.Done()
				}()
			}
		}
	} else {
		partyIds := msg.GetTo()
		for _, partyId := range partyIds {
			intPartyId, _ := strconv.Atoi(partyId.Id)
			if intPartyId-1 != index {
				wg.Add(1)
				go func() {
					isSuccess, errMsg := parties[intPartyId-1].Update(msg.(tss.ParsedMessage))
					if !isSuccess {
						log.Println("-------> party update p2p msg error", index, intPartyId-1, errMsg)
					} else {
						log.Println("-------> party update p2p msg successfully", index, intPartyId-1)
					}
					wg.Done()
				}()
			}
		}
	}
}

func updateMsgSyn(messages [3]tss.Message, parties [3]tss.Party, wg sync.WaitGroup) {
	partyMessages := [3]*list.List{list.New(), list.New(), list.New()}
	for i, msg := range messages {
		if msg.IsBroadcast() {
			for j := 0; j < 3; j++ {
				if i != j {
					partyMessages[j].PushBack(msg)
				}
			}
		} else {
			partyIds := msg.GetTo()
			for _, partyId := range partyIds {
				intPartyId, _ := strconv.Atoi(partyId.Id)
				if intPartyId-1 != i {
					partyMessages[intPartyId-1].PushBack(msg)
				}
			}
		}
	}

	for i, msgList := range partyMessages {
		no := i
		party := parties[i]
		partyMessages := msgList
		wg.Add(1)
		go func() {
			log.Println("--------> begin update message ", no, partyMessages.Len())
			for e := partyMessages.Front(); e != nil; e = e.Next() {
				isSuccess, errMsg := party.Update(e.Value.(tss.ParsedMessage))
				if !isSuccess {
					log.Println("-------> party update msg error", no, errMsg)
				} else {
					log.Println("-------> party update msg successfully", no)
				}
			}
			wg.Done()
		}()
	}
}

func saveKey(data0 keygen.LocalPartySaveData, data1 keygen.LocalPartySaveData, data2 keygen.LocalPartySaveData) {
	doSaveKey(1, data0)
	doSaveKey(2, data1)
	doSaveKey(3, data2)
}

func doSaveKey(index int, data keygen.LocalPartySaveData) {
	file, err := os.Create("data/key" + strconv.Itoa(index))
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
