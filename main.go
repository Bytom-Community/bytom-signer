package main

import (
	"fmt"
)

func main() {
	xpub, err := importKeyFromMnemonic( /*in.Alias, in.Password, */ in.Mnemonic)
	if err != nil {
		return
	}
	return

	if err := txbuilder.Sign(ctx, &x.Txs, x.Password, a.pseudohsmSignTemplate); err != nil {
		log.WithField("build err", err).Error("fail on sign transaction.")
		return
	}
}
