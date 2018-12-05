package main

import (
	"strings"

	mnem "github.com/bytom/wallet/mnemonic"
)

// EntropyLength random entropy length to generate mnemonics.
const EntropyLength = 128

var (
	ErrMnemonicLength = errors.New("mnemonic length error")
)

func importKeyFromMnemonic(mnemonic string) (*XPub, error) {
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

	return createKeyFromMnemonic(alias, auth, mnemonic)
}
