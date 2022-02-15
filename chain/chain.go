package chain

import (
	"crypto/ecdsa"
	"errors"

	"github.com/GridPlus/phonon-client/model"
)

var ErrMissingPubKey = errors.New("phonon missing pubKey")
var ErrMissingKeyIndex = errors.New("phonon missing KeyIndex")
var ErrUnknownCurrencyType = errors.New("unknown currency type")

type ChainService interface {
	DeriveAddress(p *model.Phonon) (address string, err error)
	RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, err error)
}

//Might not need this if everything is stateless
//TODO: Control this from config as well.
// func StartChainServices(currencyTypes []model.CurrencyType) (map[model.CurrencyType]*ChainService, error) {
// 	for _, currencyType := range currencyTypes {
// 		service := GetChainService(currencyType)
// 	}
// }

// /*Check the phonon's currency type and public key and returns a chain specific
// address as a hexstring
// Serves as a master DeriveAddress function that calls into specific provider interfaces*/
// //TODO: populate via config
// func DeriveAddress(p *model.Phonon) (address string, err error) {
// 	switch p.CurrencyType {
// 	case model.Ethereum:
// 		//TODO initialize this elsewhere
// 		eth := &EthChainService{}
// 		return eth.DeriveAddress(p)
// 	default:
// 		return "", ErrUnknownCurrencyType
// 	}
// }
