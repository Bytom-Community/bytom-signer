package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/bytom/crypto/ed25519/chainkd"
	mnem "github.com/bytom/wallet/mnemonic"
)

// EntropyLength random entropy length to generate mnemonics.
const EntropyLength = 128

var (
	ErrMnemonicLength = errors.New("mnemonic length error")
)

type Input struct {
	Mnemonic string `json:"mnemonic"`
}

func main() {
	input := NewInput()
	xprv, err := importKeyFromMnemonic(input.Mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("XPub:", xprv.XPub())

	return

	// if err := txbuilder.Sign(ctx, &x.Txs, x.Password, a.pseudohsmSignTemplate); err != nil {
	// 	log.WithField("build err", err).Error("fail on sign transaction.")
	// 	return
	// }
}

func NewInput() *Input {
	if len(os.Args) <= 1 {
		log.Fatal("Please provide the input file path")
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("fail to open file(%v) with err(%v)", os.Args[1], err)
	}
	defer file.Close()

	input := &Input{}
	if err := json.NewDecoder(file).Decode(input); err != nil {
		log.Fatalf("fail to decode file with err(%v)", err)
	}

	return input
}

func importKeyFromMnemonic(mnemonic string) (*chainkd.XPrv, error) {
	// checksum length = entropy length /32
	// mnemonic length = (entropy length + checksum length)/11
	if len(strings.Fields(mnemonic)) != (EntropyLength+EntropyLength/32)/11 {
		return nil, ErrMnemonicLength
	}

	// Pre validate that the mnemonic is well formed and only contains words that
	// are present in the word list
	if !mnem.IsMnemonicValid(mnemonic, "en") {
		return nil, mnem.ErrInvalidMnemonic
	}

	return createKeyFromMnemonic(mnemonic)
}

func createKeyFromMnemonic(mnemonic string) (*chainkd.XPrv, error) {
	seed := mnem.NewSeed(mnemonic, "")
	xprv, err := chainkd.NewXPrv(bytes.NewBuffer(seed))
	if err != nil {
		return nil, err
	}

	return &xprv, nil
}
