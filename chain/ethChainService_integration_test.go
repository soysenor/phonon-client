//go:build integration
// +build integration

package chain

import (
	"testing"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"
	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

//TestEthChainServiceRedeem smoke tests the basic redeem funtionality using a ganache backend.
//Ganache must be stood up manually and this test must be hand edited with valid keys to function.
func TestEthChainServiceRedeem(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	//Hand Edit Here!
	//Manually change privKeyHex and redeemAddress to values from the ganache backend used for this test
	privKeyHex := "287f9caac470d6d8c0a921f60f912f81572ebd4aee6f91c41fdd20f950b27d1f"
	redeemAddress := "0x18579269D059CD91581A01C2C3d70B16940c1BA7"

	eth, err := NewEthChainService()
	if err != nil {
		t.Error(err)
	}

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

	//Redeem to redeemAddress
	tx, err := eth.RedeemPhonon(p, privKey, redeemAddress)
	if err != nil {
		t.Error("error redeeming phonon. err: ", err)
	}

	//Validate redeemAddress received value manually
	t.Log("transaction hash: ", tx)
}
