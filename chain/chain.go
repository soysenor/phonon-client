package chain

import (
	"crypto/ecdsa"
	"errors"

	"github.com/GridPlus/phonon-client/model"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var ErrMissingPubKey = errors.New("phonon missing pubKey")
var ErrMissingKeyIndex = errors.New("phonon missing KeyIndex")
var ErrUnknownCurrencyType = errors.New("unknown currency type")

/*Check the phonon's currency type and public key and returns a chain specific
address as a hexstring*/
func DeriveAddress(p *model.Phonon) (address string, err error) {
	switch p.CurrencyType {
	case model.Ethereum:
		return deriveETHAddress(p.PubKey)
	default:
		return "", ErrUnknownCurrencyType
	}
}

//Derives an ETH address from a phonon's ECDSA Public Key
func deriveETHAddress(pubKey *ecdsa.PublicKey) (address string, err error) {
	return ethcrypto.PubkeyToAddress(*pubKey).Hex(), nil
}
