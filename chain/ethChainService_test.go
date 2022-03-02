package chain

import (
	"testing"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"
	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

//TODO: Automate this test by fetching the privKey and redeemAddress and confirming them with the test chain
func TestEthChainServiceRedeem(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	eth, err := NewEthChainService()
	if err != nil {
		t.Error(err)
	}
	//Try a transaction against ganache

	//Hardcoding against ganache for now
	//Manually construct a test phonon
	//Take privKey from address 1
	privKeyHex := "2cc946b02211c341df3fbc412a80b9fd423263363a893c600ca04e18fe1a3c89"

	privKey, err := util.ParseECCPrivKey(common.FromHex(privKeyHex))
	if err != nil {
		t.Error("could not parse hex privKey")
	}
	ganacheChainID := 1337
	p := &model.Phonon{
		KeyIndex:     1,
		PubKey:       &privKey.PublicKey,
		CurrencyType: model.Ethereum,
		ChainID:      ganacheChainID,
	}
	p.Address, err = eth.DeriveAddress(p)
	if err != nil {
		t.Error(err)
	}
	//Redeem to address 2
	redeemAddress := "0xD212e6321b53410311bCC6E3e382c0F33BDdFCbC"
	_, err = eth.RedeemPhonon(p, privKey, redeemAddress)
	if err != nil {
		t.Error("error redeeming phonon. err: ", err)
	}

}
