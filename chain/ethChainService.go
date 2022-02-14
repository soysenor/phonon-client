package chain

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"net/http"
	"net/url"

	"github.com/GridPlus/phonon-client/config"
	"github.com/GridPlus/phonon-client/model"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)

type EthChainService struct {
	APIKey string
}

func NewEthChainService() (*EthChainService, error) {
	config, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	//TODO: Check API_KEY against chain instead of this default check
	if config.EthChainServiceApiKey == "" {
		return nil, errors.New("no APIKey found for EthChainService")
	}

	ethchainSrv := &EthChainService{
		APIKey: config.EthChainServiceApiKey,
	}
	log.Debugf("successfully loaded EthChainServiceConfig: %+v", ethchainSrv)

	return ethchainSrv, nil
}

//Derives an ETH address from a phonon's ECDSA Public Key
func (eth *EthChainService) DeriveAddress(p *model.Phonon) (address string, err error) {
	return ethcrypto.PubkeyToAddress(*p.PubKey).Hex(), nil
}

func (eth *EthChainService) RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, privKeyString string, err error) {
	var txHex string
	//Build eth transaction request as hex string
	fromAddress := accounts.Account{
		Address: common.HexToAddress(p.Address),
	}

	toAddress := accounts.Account{
		Address: common.HexToAddress(redeemAddress),
	}

	signer := types.NewLondonSigner(big.NewInt(int64(p.ChainID)))
	signedTx, err := types.SignNewTx(privKey, signer, &types.LegacyTx{
		Nonce:    0,              //TODO: check this is correct
		GasPrice: big.NewInt(40), //TODO: fetch this from somewhere
		Gas:      300,            //TODO: Set this rationally
		To:       &toAddress.Address,
		Data:     nil, //TODO: ?
		//V, R, S
	})
	//Convert this signedTX to hex

	//Format transaction request
	sendTransactionUrl, err := url.Parse("https://eth-blockbook.nownodes.io/api/v2/sendtx")
	if err != nil {
		return "", "", err
	}
	sendTransactionUrl.Path += txHex
	resp, err := http.Get(sendTransactionUrl.EscapedPath())
	if err != nil {
		return "", "", err
	}

	//TODO: Test that this works somehow
	//Parse Response
	return "", "", nil
}
