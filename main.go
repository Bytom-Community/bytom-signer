package main

import (
	// "fmt"
	"bytes"
	"errors"
	"strings"

	"github.com/bytom/crypto/ed25519/chainkd"
	mnem "github.com/bytom/wallet/mnemonic"
)

// EntropyLength random entropy length to generate mnemonics.
const EntropyLength = 128

var (
	ErrMnemonicLength = errors.New("mnemonic length error")

	mnemonic = ""
)

func main() {
	xprv, err := importKeyFromMnemonic(mnemonic)
	if err != nil {
		return
	}
	return

	// if err := txbuilder.Sign(ctx, &x.Txs, x.Password, a.pseudohsmSignTemplate); err != nil {
	// 	log.WithField("build err", err).Error("fail on sign transaction.")
	// 	return
	// }
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
