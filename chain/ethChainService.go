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
	"github.com/GridPlus/phonon-client/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
)

type EthChainService struct {
	APIKey   string
	NodeURL  string
	gasLimit uint64
	cl       *ethclient.Client
}

func NewEthChainService() (*EthChainService, error) {
	config, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	// //TODO: Check API_KEY against chain instead of this default check
	// if config.EthChainServiceApiKey == "" {
	// 	return nil, errors.New("no APIKey found for EthChainService")
	// }

	//TODO: Change this based on chainID?
	cl, err := ethclient.Dial(config.EthNodeURL)
	if err != nil {
		log.Error("could not dial eth chain provider: ", err)
		return nil, err
	}

	ethchainSrv := &EthChainService{
		APIKey:   config.EthChainServiceApiKey,
		gasLimit: uint64(21000), //Setting to default magic value for now
		cl:       cl,
	}
	log.Debugf("successfully loaded EthChainServiceConfig: %+v", ethchainSrv)

	return ethchainSrv, nil
}

//Derives an ETH address from a phonon's ECDSA Public Key
func (eth *EthChainService) DeriveAddress(p *model.Phonon) (address string, err error) {
	return ethcrypto.PubkeyToAddress(*p.PubKey).Hex(), nil
}

func (eth *EthChainService) RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, err error) {
	//Check that pubkey listed in metadata matches pubKey derived from phonon's private key
	if !p.PubKey.Equal(privKey.Public()) {
		log.Error("phonon pubkey metadata and pubkey derived from redemption privKey did not match. err: ", err)
		log.Error("metadata pubkey: ", util.ECCPubKeyToHexString(p.PubKey))
		log.Error("privKey derived key: ", util.ECCPubKeyToHexString(&privKey.PublicKey))
		return "", errors.New("pubkey metadata and redemption private key did not match")
	}

	ctx := context.Background()

	//Collect on chain details for redeem
	nonce, onChainBalance, suggestedGasPrice, err := eth.fetchPreTransactionInfo(ctx, common.HexToAddress(p.Address))
	if err != nil {
		return "", err
	}
	redeemValue := eth.calcRedemptionValue(onChainBalance, suggestedGasPrice)
	log.Debug("transaction redemption value is: ", redeemValue)

	//If gas would cost more than the value in the phonon, return error
	if suggestedGasPrice.Cmp(onChainBalance) != -1 {
		return "", errors.New("phonon not large enough to pay gas for redemption")
	}

	ganacheChainID := big.NewInt(1337)
	tx, err := eth.submitLegacyTransaction(ctx, nonce, ganacheChainID, common.HexToAddress(redeemAddress), redeemValue, eth.gasLimit, suggestedGasPrice, privKey)
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
	return string(tx.Data()), nil
}

func (eth *EthChainService) fetchPreTransactionInfo(ctx context.Context, fromAddress common.Address) (nonce uint64, balance *big.Int, suggestedGas *big.Int, err error) {
	nonce, err = eth.cl.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		log.Error("could not fetch pending nonce for eth account")
		return 0, nil, nil, err
	}
	log.Debug("pending nonce: ", nonce)
	//Check actual balance of phonon
	balance, err = eth.cl.PendingBalanceAt(ctx, fromAddress)
	if err != nil {
		log.Error("could not fetch on chain Phonon value")
		return 0, nil, nil, err
	}
	log.Debug("on chain balance: ", balance)
	suggestedGasPrice, err := eth.cl.SuggestGasPrice(ctx)
	if err != nil {
		log.Error("error fetching suggested gas price: ", err)
		return 0, nil, nil, err
	}
	log.Debug("suggest gas price is: ", suggestedGasPrice)
	return nonce, balance, suggestedGasPrice, nil
}

func (eth *EthChainService) calcRedemptionValue(balance *big.Int, gasPrice *big.Int) *big.Int {
	valueMinusGas := big.NewInt(0)
	estimatedGasCost := big.NewInt(0)
	gasLimit := int(eth.gasLimit) //Magic number from examples
	return valueMinusGas.Sub(balance, estimatedGasCost.Mul(gasPrice, big.NewInt(int64(gasLimit))))
}

func (eth *EthChainService) submitLegacyTransaction(ctx context.Context, nonce uint64, chainID *big.Int, redeemAddress common.Address, redeemValue *big.Int, gasLimit uint64, gasPrice *big.Int, privKey *ecdsa.PrivateKey) (*types.Transaction, error) {
	//Submit transaction
	//build transaction payload
	tx := types.NewTransaction(nonce, redeemAddress, redeemValue, gasLimit, gasPrice, nil)
	//Sign it
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privKey)
	if err != nil {
		return signedTx, err
	}

	//Send the transaction through the ETH client
	err = eth.cl.SendTransaction(ctx, signedTx)
	if err != nil {
		return signedTx, err
	}
	return signedTx, nil
}

//London Signing Code
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
