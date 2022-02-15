package chain

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"

	// "net/http"
	// "net/url"

	"github.com/GridPlus/phonon-client/config"
	"github.com/GridPlus/phonon-client/model"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
)

type EthChainService struct {
	APIKey  string
	NodeURL string
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
		APIKey:  config.EthChainServiceApiKey,
		NodeURL: config.EthNodeURL,
	}
	log.Debugf("successfully loaded EthChainServiceConfig: %+v", ethchainSrv)

	return ethchainSrv, nil
}

//Derives an ETH address from a phonon's ECDSA Public Key
func (eth *EthChainService) DeriveAddress(p *model.Phonon) (address string, err error) {
	return ethcrypto.PubkeyToAddress(*p.PubKey).Hex(), nil
}

//TODO: Fix all error handling values
func (eth *EthChainService) RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, err error) {
	//TODO: Check that privKey matches derived pubKey and address

	//Build eth transaction request as hex string
	fromAccount := accounts.Account{
		Address: common.HexToAddress(p.Address),
	}

	log.Debug("fromAccount address: ", p.Address)
	toAddress := accounts.Account{
		Address: common.HexToAddress(redeemAddress),
	}

	//Collect on chain details for redeem
	//TODO: cache this
	ctx := context.Background()
	//Ganache Connection
	cl, err := ethclient.Dial(eth.NodeURL)

	if err != nil {
		log.Error("could not dial eth node at")
		return "", err
	}
	nonce, err := cl.PendingNonceAt(ctx, fromAccount.Address)
	if err != nil {
		log.Error("could not fetch pending nonce for eth account")
		return "", err
	}
	log.Debug("pending nonce: ", nonce)
	//Check actual balance of phonon
	onChainPhononValue, err := cl.PendingBalanceAt(ctx, fromAccount.Address)
	if err != nil {
		log.Error("could not fetch on chain Phonon value")
		return "", err
	}
	log.Debug("onChainValue: ", onChainPhononValue)
	suggestedGasPrice, err := cl.SuggestGasPrice(ctx)
	if err != nil {
		log.Error("error fetching suggested gas price: ", err)
		return "", err
	}
	log.Debug("suggest gas price is: ", suggestedGasPrice)

	phononValue := onChainPhononValue
	//If gas would cost more than the value in the phonon, return error
	if suggestedGasPrice.Cmp(phononValue) != -1 {
		return "", errors.New("phonon not large enough to pay gas for redemption")
	}

	//London EIP-1559 gas
	// suggestedGasTipCap, err := cl.SuggestGasTipCap(ctx)
	// if err != nil {
	// 	log.Error("error fetching suggested gas tip cap. err: ", err)
	// 	return "", "", err
	// }
	// log.Debug("suggested gas tip cap is: ", suggestedGasTipCap)
	//TODO: check metadata denomination against actual on chain value
	// phononValue := big.NewInt(int64(p.Denomination.Value()))

	//London EIP-1559 Gas estimation attempt
	// //Calculate gas costs and subtract from max for final redeem value
	// gasLimit := 21000
	// bigGasLimit := big.NewInt(int64(gasLimit))
	// var totalGasPrice *big.Int
	// totalGasPrice = totalGasPrice.Add(suggestedGasPrice, suggestedGasTipCap)
	// valueMinusGas = valueMinusGas.Sub(phononValue, valueMinusGas.Mul(totalGasPrice, bigGasLimit))

	valueMinusGas := big.NewInt(0)
	estimatedGasCost := big.NewInt(0)
	gasLimit := 21000 //Magic number from examples
	valueMinusGas = valueMinusGas.Sub(onChainPhononValue, estimatedGasCost.Mul(suggestedGasPrice, big.NewInt(int64(gasLimit))))

	log.Debug("transaction value minus gas is: ", valueMinusGas)
	tx := types.NewTransaction(nonce, toAddress.Address, valueMinusGas, uint64(gasLimit), suggestedGasPrice, nil)
	//London EIP-1559 Transaction formation
	// tx := types.NewTx(&types.DynamicFeeTx{
	// 	ChainID:   ganacheChainID,
	// 	Nonce:     nonce,
	// 	GasFeeCap: suggestedGasPrice,
	// 	GasTipCap: suggestedGasTipCap, //TODO: calc this
	// 	Gas:       uint64(21000),
	// 	To:        &toAddress.Address,
	// 	Value:     valueMinusGas,
	// })

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(int64(p.ChainID))), privKey)
	if err != nil {
		return "", err
	}

	//Send the transaction through the ETH client
	err = cl.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", err
	}

	//Nownodes format. probably deprecate
	// //Format transaction request
	// sendTransactionUrl, err := url.Parse("https://eth-blockbook.nownodes.io/api/v2/sendtx")
	// if err != nil {
	// 	return "", "", err
	// }
	// sendTransactionUrl.Path += txHex
	// resp, err := http.Get(sendTransactionUrl.EscapedPath())
	// if err != nil {
	// 	return "", "", err
	// }

	//TODO: Test that this works somehow
	//Parse Response
	return "", nil
}
