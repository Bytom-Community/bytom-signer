package main

import (
// "fmt"
)

var (
	mnemonic = ""
)

func main() {
	xpub, err := importKeyFromMnemonic( /*in.Alias, in.Password, */ mnemonic)
	if err != nil {
		return
	}
	return

	// if err := txbuilder.Sign(ctx, &x.Txs, x.Password, a.pseudohsmSignTemplate); err != nil {
	// 	log.WithField("build err", err).Error("fail on sign transaction.")
	// 	return
	// }
}
