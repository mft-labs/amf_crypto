/****************************************************************************
 *
 * Copyright (C) Agile Data, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by MFTLABS <code@mftlabs.io>
 *
 ****************************************************************************/
package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func DecryptPrivateKey(encKeyData []byte, passphrase string) ([]byte, error) {
	var keydata []byte
	// decrypt passphrase from config file
	passphrase, err := Decrypt(passphrase)
	if err != nil {
		return keydata, errors.New(fmt.Sprintf("error decrypting private key passphrase [%s]", err.Error()))
	}
	block, _ := pem.Decode(encKeyData)
	// decrypt private key to der form
	der, err := x509.DecryptPEMBlock(block, []byte(passphrase))
	if err != nil {
		return keydata, errors.New(fmt.Sprintf("private key decrypt failed [%s]", err.Error()))
	}
	// get private key type
	pkey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return keydata, errors.New(fmt.Sprintf("invalid private key [%s]", err.Error()))
	}
	// rebuild key block w/o passphrase
	keydata = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
		},
	)
	return keydata, nil
}
