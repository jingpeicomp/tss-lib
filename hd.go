package main

import (
	"C"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"encoding/hex"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/ckd"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"os"
	"runtime"
	"strconv"
)

func main() {
	msgDigest := []byte("Hello web3 world!")
	msg := &big.Int{}
	msg.SetBytes(msgDigest)

	keys := make([]keygen.LocalPartySaveData, 0, 3)
	for j := 0; j < 3; j++ {
		keys = append(keys, loadKey(j))
	}

	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	fillBytes(common.GetRandomPositiveInt(max32b), chainCode)

	// generate HD key pair
	il, extendedChildPk, err := derivingPubkeyFromPath(keys[0].ECDSAPub, chainCode, []uint32{44, 60, 0, 0, 1}, btcec.S256())
	childPubkey, childAddr := parsePublicKey(&extendedChildPk.PublicKey)
	log.Println("-------> child pub key ", childPubkey, childAddr)
	if err != nil {
		log.Println("Error deriving the child public key", err)
	}
	keyDerivationDelta := il
	err = signing.UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keys, &extendedChildPk.PublicKey, btcec.S256())
	if err != nil {
		log.Println("there should not be an error setting the derived keys", err)
	}

	partyIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("1", " ", big.NewInt(1)),
		tss.NewPartyID("2", " ", big.NewInt(2)), tss.NewPartyID("3", " ", big.NewInt(3))})
	p2pCtx := tss.NewPeerContext(partyIDs)
	parties := make([]*signing.LocalParty, 0, len(partyIDs))
	outCh := make(chan tss.Message, len(partyIDs))
	endCh := make(chan common.SignatureData, len(partyIDs))
	for i := 0; i < len(partyIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[i], len(partyIDs), 1)
		P := signing.NewLocalPartyWithKDD(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			err := P.Start()
			if err == nil {
				log.Println()
				log.Println("------> start party successfully: ", P.PartyID().Id)
			} else {
				log.Println("------> start party error: ", P.PartyID().Id, err)
			}
		}(P)
	}

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

func fillBytes(x *big.Int, buf []byte) []byte {
	b := x.Bytes()
	if len(b) > len(buf) {
		panic("buffer too small")
	}
	offset := len(buf) - len(b)
	for i := range buf {
		if i < offset {
			buf[i] = 0
		} else {
			buf[i] = b[i-offset]
		}
	}
	return buf
}

func derivingPubkeyFromPath(masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	pk := ecdsa.PublicKey{
		Curve: ec,
		X:     masterPub.X(),
		Y:     masterPub.Y(),
	}

	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}

	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, ec.Params().N, ec)
}

func parsePublicKey(pubKey *ecdsa.PublicKey) (string, string) {
	publicKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hexStr := hex.EncodeToString(publicKeyBytes)

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	addressBytes := hash.Sum(nil)[12:]
	address := ethcommon.BytesToAddress(addressBytes)
	addressStr := address.Hex()

	return hexStr, addressStr
}
