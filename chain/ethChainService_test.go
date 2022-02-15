package chain

import (
	"testing"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"
	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

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
	privKeyHex := "bd3b4df06b05efe4c5859c015b8d780e7a2e0f25a9b2bfaa1e60902b51fc0db6"

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
	redeemAddress := "0x631816506EE68DcebCcf2d55da10f842b1862534"
	_, err = eth.RedeemPhonon(p, privKey, redeemAddress)
	if err != nil {
		t.Error("error redeeming phonon. err: ", err)
	}

}
