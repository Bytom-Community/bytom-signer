package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/bytom/crypto/ed25519/chainkd"
	mnem "github.com/bytom/wallet/mnemonic"
)

const EntropyLength = 128

var (
	ErrMnemonicLength = errors.New("mnemonic length error")
)

type Input struct {
	Mnemonic            string               `json:"mnemonic"`
	SigningInstructions []SigningInstruction `json:"signing_instructions"`
}

type SigningInstruction struct {
	DerivationPath []string `json:"derivation_path"`
	SignData       []string `json:"sign_data"`
}

type Signatures struct {
	Signature []string
}

func main() {
	input := NewInput()
	xprv, err := importKeyFromMnemonic(input.Mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("root XPub:", xprv.XPub())
	for i, instruction := range input.SigningInstructions {
		log.Printf("SigningInstruction[%d]:", i)
		path := make([][]byte, len(instruction.DerivationPath))
		for j, o := range instruction.DerivationPath {
			b, err := hex.DecodeString(o)
			if err != nil {
				log.Printf("err: %v", err)
			}

			path[j] = b
		}

		key := xprv.Derive(path)
		log.Printf("\tDerivedXPub: %v", key.XPub())
		for j, data := range instruction.SignData {
			log.Printf("\tsign_data[%d]: %s", j, data)
			b, err := hex.DecodeString(data)
			if err != nil {
				log.Printf("err: %v", err)
			}

			log.Printf("\tsigned: %v", hex.EncodeToString(key.Sign(b)))
		}
	}
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
