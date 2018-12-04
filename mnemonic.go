package main

func importKeyFromMnemonic() (*XPub, error) {
	// checksum length = entropy length /32
	// mnemonic length = (entropy length + checksum length)/11
	if len(strings.Fields(mnemonic)) != (EntropyLength+EntropyLength/32)/11 {
		return nil, ErrMnemonicLength
	}

	normalizedAlias := strings.ToLower(strings.TrimSpace(alias))
	if ok := h.cache.hasAlias(normalizedAlias); ok {
		return nil, ErrDuplicateKeyAlias
	}

	// Pre validate that the mnemonic is well formed and only contains words that
	// are present in the word list
	if !mnem.IsMnemonicValid(mnemonic, language) {
		return nil, mnem.ErrInvalidMnemonic
	}

	xpub, err := h.createKeyFromMnemonic(alias, auth, mnemonic)
	if err != nil {
		return nil, err
	}

	h.cache.add(*xpub)
	return xpub, nil

}
