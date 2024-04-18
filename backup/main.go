// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package backup

import (
	"C"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/ipfs/go-log"
	"os"
	"time"
)

func main1() {
	var level, _ = log.LevelFromString("debug")
	log.SetAllLoggers(level)
	log.SetupLogging()
	keygen.GeneratePreParams(3 * time.Minute, true)

	data0 := loadKey("/Users/liuzhaoming/百度云同步盘/mac同步/project/study/java_call_go/java_call_go/src/main/data/session-1686363168946_1.key")
	data1 := loadKey("/Users/liuzhaoming/百度云同步盘/mac同步/project/study/java_call_go/java_call_go/src/main/data/session-1686363168946_2.key")
	//data2 := loadKey("/Users/liuzhaoming/百度云同步盘/mac同步/project/study/java_call_go/java_call_go/src/main/data/session-1686363168946_3.key")

	privateKey, _ := reconstruct(1, tss.S256(), [2]keygen.LocalPartySaveData{data0, data1})
	fmt.Println("reconstruct finish", privateKey)
	fmt.Println(privateKey.PublicKey)
	fmt.Println(hex.EncodeToString(privateKey.D.Bytes()))

	time.Sleep(time.Minute)
}

func loadKey(fileName string) keygen.LocalPartySaveData {
	content, _ := file2Bytes(fileName)
	var key keygen.LocalPartySaveData
	dec := gob.NewDecoder(bytes.NewReader(content[28:]))
	err := dec.Decode(&key)
	if err != nil {
		fmt.Println(err)
	}
	return key
}

func file2Bytes(filename string) ([]byte, error) {
	// File
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// FileInfo:
	stats, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// []byte
	data := make([]byte, stats.Size())
	count, err := file.Read(data)
	if err != nil {
		return nil, err
	}
	fmt.Printf("read file %s len: %d \n", filename, count)
	return data, nil
}

func reconstruct(threshold int, ec elliptic.Curve, shares [2]keygen.LocalPartySaveData) (*ecdsa.PrivateKey, error) {
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
