package chain

import (
	"crypto/ecdsa"

	"github.com/GridPlus/phonon-client/model"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type EthChainService struct {
	APIKey string
}

func NewEthChainService() *EthChainService {
	return &EthChainService{}
}

//Derives an ETH address from a phonon's ECDSA Public Key
func (eth *EthChainService) DeriveAddress(p *model.Phonon) (address string, err error) {
	return ethcrypto.PubkeyToAddress(*p.PubKey).Hex(), nil
}

func (eth *EthChainService) RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, privKeyString string, err error) {
	return "", "", nil
}
