package main

import (
	"fmt"
)

func main() {
	xpub, err := a.wallet.Hsm.ImportKeyFromMnemonic(in.Alias, in.Password, in.Mnemonic, in.Language)
	if err != nil {
		return
	}
	return

	if err := txbuilder.Sign(ctx, &x.Txs, x.Password, a.pseudohsmSignTemplate); err != nil {
		log.WithField("build err", err).Error("fail on sign transaction.")
		return
	}
}
