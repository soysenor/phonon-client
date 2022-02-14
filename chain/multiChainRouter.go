package chain

import (
	"crypto/ecdsa"

	"github.com/GridPlus/phonon-client/model"
)

/*MultiChainRouter is a ChainService supporting multiple currencyTypes by
encapsulating a specific hardcoded collection of ChainServices keyed by CurrencyType*/
type MultiChainRouter struct {
	chainServices map[model.CurrencyType]ChainService
}

//Initialize all supported chain services at start
//TODO: remove dependency on InitBuiltinChainServices()
func NewMultiChainRouter() (*MultiChainRouter, error) {
	mcr := &MultiChainRouter{
		chainServices: make(map[model.CurrencyType]ChainService),
	}
	err := mcr.InitBuiltinChainServices()
	if err != nil {
		return nil, err
	}
	return mcr, nil
}

//TODO: Use a configurable function instead of this hardcoded one
func (mcr *MultiChainRouter) InitBuiltinChainServices() (err error) {
	mcr.chainServices[model.Ethereum], err = NewEthChainService()
	if err != nil {
		return err
	}
	//TODO: BTC
	return nil
}

//InitChainService and LoadChainService enable dynamic loading of different chain providers

//Detect the chain service that should be used for each phonon based on CurrencyType
//TODO: Setup a config file where this can be user defined
//TODO: Change CurrencyType to AssetType
//TODO: Change schema to allow for multiple assets to be defined on one phonon e.g. NFT + ETH at the same address.
//Maybe this can just be done with different currencyTypes for NFT + ETH and NFT w/ no ETH
func InitChainService(cur model.CurrencyType) (ChainService, error) {
	switch cur {
	case model.Ethereum:
		return NewEthChainService()
	default:
		return nil, ErrUnknownCurrencyType
	}
}

func (mcr *MultiChainRouter) LoadChainService(cur model.CurrencyType) (chain ChainService, err error) {
	//Look for existing chain service for currencyType
	//If it doesn't exist yet, lazy load it
	chain, ok := mcr.chainServices[cur]
	if !ok {
		chain, err = InitChainService(cur)
		if err != nil {
			return nil, err
		}
		mcr.chainServices[cur] = chain
	}
	return chain, nil
}

//ChainService interface methods
func (mcr *MultiChainRouter) DeriveAddress(p *model.Phonon) (address string, err error) {
	chain, err := mcr.LoadChainService(p.CurrencyType)
	if err != nil {
		return "", err
	}
	return chain.DeriveAddress(p)
}

func (mcr *MultiChainRouter) RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, privKeyString string, err error) {
	chain, err := mcr.LoadChainService(p.CurrencyType)
	if err != nil {
		return "", "", err
	}
	return chain.RedeemPhonon(p, privKey, redeemAddress)
}
