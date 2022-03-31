package chain

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"
	"github.com/GridPlus/phonon-client/tlv"
	"github.com/GridPlus/phonon-client/card"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	log "github.com/sirupsen/logrus"
	erc721 "github.com/soysenor/eth-go-bindings/erc721"
	erc20 "github.com/soysenor/eth-go-bindings/erc20"
)

//Composite interface supporting all needed EVM RPC calls
type EthChainInterface interface {
	bind.ContractTransactor
	ethereum.ChainStateReader
	bind.ContractBackend
}
type EthChainService struct {
	gasLimit  uint64
	cl        EthChainInterface //*ethclient.Client // //bind.ContractTransactor
	clChainID int
}

func NewEthChainService() (*EthChainService, error) {
	ethchainSrv := &EthChainService{
		gasLimit: uint64(21000), //Setting to default magic value for now
	}
	log.Debugf("successfully loaded EthChainServiceConfig: %+v", ethchainSrv)

	return ethchainSrv, nil
}

//Derives an ETH address from a phonon's ECDSA Public Key
func (eth *EthChainService) DeriveAddress(p *model.Phonon) (address string, err error) {
	return ethcrypto.PubkeyToAddress(*p.PubKey).Hex(), nil
}

func (eth *EthChainService) RedeemPhonon(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, err error) {
	err = eth.ValidateRedeemData(p, privKey, redeemAddress)
	if err != nil {
		log.Error("phonon did not contain complete data for redemption: ", err)
		return "", err
	}

	//Will validate that we have a valid RPC endpoint for the given p.ChainID
	err = eth.dialRPCNode(p.ChainID)
	if err != nil {
		return "", err
	}
	ctx := context.Background()

	switch p.CurrencyType {
		case model.Ethereum:
			tx, err := eth.redeemETH(p, ctx, privKey, redeemAddress)
			if err != nil {
				return "", err
			}
			return tx, nil

		case model.EthereumERC721, model.EthereumERC20:
			tx, err := eth.redeemToken(p, ctx, privKey, redeemAddress)
			if err != nil {
				return "", err
			}
			return tx, nil
	}

	return "", errors.New("cannot auto redeem this ethereum asset type")
}

func (eth *EthChainService) VerifyBalance(p *model.Phonon) (balance bool, err error) {
	// Get Address for Phonon
	err = eth.checkFetchFromAddress(p)
	if err != nil {
		return false, err
	}

	//Validate if we have valid RPC endpoint
	if p.ChainID == 0 {
		return false, errors.New("cannot establish connection with RPC node")
	}

	err = eth.dialRPCNode(p.ChainID)
	if err != nil {
		return false, err
	}
	ctx := context.Background()

	//Check additional for assets, if applicable
	switch p.CurrencyType {
		case model.Ethereum:
			check, err := eth.checkETHBalance(ctx, p)
			if err != nil {
				return false, err
			}
			return check, nil

		case model.EthereumERC721:
			check, err := eth.checkERC721Balance(ctx, p)
			if err != nil {
				return false, err
			}
			return check, nil

		case model.EthereumERC20:
			check, err := eth.checkERC20Balance(ctx, p)
			if err != nil {
				return false, err
			}
			return check, nil
	}

	//Parse Response
	return true, nil
}

//ReconcileRedeemData validates the input data to ensure it contains all that's needed for a successful redemption.
//It will update the phonon data structure with a derived address if necessary
func (eth *EthChainService) ValidateRedeemData(p *model.Phonon, privKey *ecdsa.PrivateKey, redeemAddress string) (err error) {
	//Check that pubkey listed in metadata matches pubKey derived from phonon's private key
	if !p.PubKey.Equal(privKey.Public()) {
		log.Error("phonon pubkey metadata and pubkey derived from redemption privKey did not match. err: ", err)
		log.Error("metadata pubkey: ", util.ECCPubKeyToHexString(p.PubKey))
		log.Error("privKey derived key: ", util.ECCPubKeyToHexString(&privKey.PublicKey))
		return errors.New("pubkey metadata and redemption private key did not match")
	}

	// Get Address for Phonon
	err = eth.checkFetchFromAddress(p)
	if err != nil {
		return err
	}

	//Check that redeemAddress is valid
	//Just checks for correct address length, works with or without 0x prefix
	valid := common.IsHexAddress(redeemAddress)
	if !valid {
		return errors.New("redeem address invalid")
	}

	return nil
}

//dialRPCNode establishes a connection to the proper RPC node based on the chainID
func (eth *EthChainService) dialRPCNode(chainID int) (err error) {
	log.Debugf("ethChainID: %v, chainID: %v\n", eth.clChainID, chainID)
	var RPCEndpoint string
	//If chainID is already set, correct RPC node is already connected
	if eth.clChainID != 0 && eth.clChainID == chainID {
		return nil
	}
	switch chainID {
	case 1: //Mainnet
		//untested
		RPCEndpoint = "https://eth-mainnet.gateway.pokt.network/v1/lb/621e9e234e140e003a32b8ba"
	case 3: //Ropsten
		//untested
		RPCEndpoint = "https://eth-ropsten.gateway.pokt.network/v1/lb/621e9e234e140e003a32b8ba"
	case 4: //Rinkeby
		RPCEndpoint = "https://eth-rinkeby.gateway.pokt.network/v1/lb/621e9e234e140e003a32b8ba"
	case 42: //Kovan
		RPCEndpoint = "https://poa-kovan.gateway.pokt.network/v1/lb/621e9e234e140e003a32b8ba"
	case 1337: //Local Ganache
		RPCEndpoint = "HTTP://127.0.0.1:8545"
	default:
		log.Debug("unsupported eth chainID requested")
		return errors.New("eth chainID unsupported")
	}
	eth.cl, err = ethclient.Dial(RPCEndpoint)
	if err != nil {
		log.Errorf("could not dial eth chain provider at endpoint %v: %v\n", RPCEndpoint, err)
		return err
	}

	//If connection succeeded, set currently configured chainID
	eth.clChainID = chainID
	log.Debug("eth chain ID set to ", chainID)
	return nil
}

func (eth *EthChainService) redeemETH(p *model.Phonon, ctx context.Context, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, err error) {
	//Collect on chain details for redeem
	nonce, onChainBalance, suggestedGasPrice, err := eth.fetchPreTransactionInfo(ctx, common.HexToAddress(p.Address))
	if err != nil {
		return "", err
	}
	redeemValue := eth.calcRedemptionValue(onChainBalance, suggestedGasPrice)
	log.Debug("transaction redemption value is: ", redeemValue)

	//If gas would cost more than the value in the phonon, return error
	if suggestedGasPrice.Cmp(onChainBalance) != -1 {
		log.Error("phonon not large enough to pay gas for redemption")
		return "", errors.New("phonon not large enough to pay gas for redemption")
	}

	tx, err := eth.submitLegacyTransaction(ctx, nonce, big.NewInt(int64(p.ChainID)), common.HexToAddress(redeemAddress), redeemValue, eth.gasLimit, suggestedGasPrice, privKey, nil)
	if err != nil {
		return "", err
	}

	//Parse Response
	return tx.Hash().String(), nil
}

func (eth *EthChainService) redeemToken(p *model.Phonon, ctx context.Context, privKey *ecdsa.PrivateKey, redeemAddress string) (transactionData string, err error) {
	//TODO: would not expect eth to be in erc20 or erc721 phonon. redemption
	//should be preceeded by a transfer of eth to the phonon address - likely to
	//be done in web app before sending redemption command from webui to client

	// collect on chain details
	fromAddress := common.HexToAddress(p.Address)
	nonce, onChainBalance, suggestedGasPrice, err := eth.fetchPreTransactionInfo(ctx, fromAddress)
	if err != nil {
		return "", err
	}

	// get tags with erc721 and erc21 contract details
	packet := tlv.EncodeTLVList(p.ExtendedTLV...)
	parsed, err := tlv.ParseTLVPacket(packet)
	if err != nil {
		return "", err
	}
	// get contract address
	contractBytes, err := parsed.FindTag(card.TagPhononContractAddress)
	if err != nil {
		return "", err
	}
	contractAddress := common.HexToAddress(string(contractBytes))

	// get contract method and token quantity or id
	var method string
	var amount []byte

	if p.CurrencyType == model.EthereumERC20 {
		method = "transfer(address,uint256)"
		amount = p.Denomination.Value().Bytes()

	} else if p.CurrencyType == model.EthereumERC721 {
		method = "safeTransferFrom(address,address,uint256)"
		idbytes, err := parsed.FindTag(card.TagPhononContractTokenID)
		if err != nil {
			return "", err
		}
		amount = idbytes

	} else {
		return "", errors.New("no known method to call for this currency type")
	}

	// prepare data packet
	fnSig := []byte(method)
	hash := sha3.NewLegacyKeccak256()
	hash.Write(fnSig)
  methodID := hash.Sum(nil)[:4]
	toAddress := common.HexToAddress(redeemAddress)
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	paddedAmount := common.LeftPadBytes(amount, 32)

	// build data packet including additional address parameter for erc721
	var data []byte
  data = append(data, methodID...)
	if p.CurrencyType == model.EthereumERC721 {
		paddedFromAddress := common.LeftPadBytes(fromAddress.Bytes(), 32)
		data = append(data, paddedFromAddress...)
	}
  data = append(data, paddedAddress...)
  data = append(data, paddedAmount...)


	gasLimit, err := eth.cl.EstimateGas(ctx, ethereum.CallMsg{
		To:   &contractAddress,
		Data: data,
	})
	if err != nil {
		return "", errors.New("cannot estimate gaslimit for redemption")
	}

	tx, err := eth.submitLegacyTransaction(ctx, nonce, big.NewInt(int64(p.ChainID)), common.HexToAddress(redeemAddress), big.NewInt(0), gasLimit, suggestedGasPrice, privKey, data)
	if err != nil {
		return "", err
	}

	//TODO: if for some reason there is a bunch of eth in the erc20 phonon
	//it should be captured by a subsequent redeemETH
	leftOverValue := eth.calcRedemptionValue(onChainBalance, big.NewInt(int64(gasLimit)))
	log.Debug("potential leftover eth in wallet: ", leftOverValue)

	return tx.Hash().String(), nil
}

func (eth *EthChainService) fetchPreTransactionInfo(ctx context.Context, fromAddress common.Address) (nonce uint64, balance *big.Int, suggestedGas *big.Int, err error) {
	nonce, err = eth.cl.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		log.Error("could not fetch pending nonce for eth account")
		return 0, nil, nil, err
	}
	log.Debug("pending nonce: ", nonce)
	//Check actual balance of phonon
	balance, err = eth.cl.BalanceAt(ctx, fromAddress, nil)
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
	gasLimit := int(eth.gasLimit)
	return valueMinusGas.Sub(balance, estimatedGasCost.Mul(gasPrice, big.NewInt(int64(gasLimit))))
}

func (eth *EthChainService) submitLegacyTransaction(ctx context.Context, nonce uint64, chainID *big.Int, redeemAddress common.Address, redeemValue *big.Int, gasLimit uint64, gasPrice *big.Int, privKey *ecdsa.PrivateKey, data []byte) (*types.Transaction, error) {
	//Submit transaction
	//build transaction payload
	tx := types.NewTransaction(nonce, redeemAddress, redeemValue, gasLimit, gasPrice, data)
	//Sign it
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privKey)
	if err != nil {
		log.Error("error forming signed transaction: ", err)
		return signedTx, err
	}

	//Send the transaction through the ETH client
	err = eth.cl.SendTransaction(ctx, signedTx)
	if err != nil {
		log.Error("error sending transaction: ", err)
		return signedTx, err
	}
	log.Debug("sent redeem transaction")
	return signedTx, nil
}

func (eth *EthChainService) checkFetchFromAddress(p *model.Phonon) error {
	var err error
	if p.Address == "" {
		p.Address, err = eth.DeriveAddress(p)
		if err != nil {
			log.Error("unable to derive source address for redemption: ", err)
			return err
		}
	}
	return nil
}

func (eth *EthChainService) checkETHBalance(ctx context.Context, p *model.Phonon) (check bool, err error) {

	// Get Balance at Phonon Public Address
	response, err := eth.cl.BalanceAt(ctx, common.HexToAddress(p.Address), nil)
	if err != nil {
		return false, err
	}
	// Get Phonon Denomination
	denom := new(big.Int).Mul(p.Denomination.Value(), big.NewInt(params.Ether))

	// Compare Denomination and Balance
	compare := response.Cmp(denom)
	if (compare < 0) {
		return false, errors.New("phonon balance is insufficient")
	}

	return true, nil
}

func (eth *EthChainService) checkERC721Balance(ctx context.Context, p *model.Phonon) (check bool, err error) {

	packet := tlv.EncodeTLVList(p.ExtendedTLV...)

	// Parse TLV Collection
	parsed, err := tlv.ParseTLVPacket(packet)
	if err != nil {
		return false, err
	}

	// Get Bytes Value for ERC721 Contract Address Tag then format
	contractBytes, err := parsed.FindTag(card.TagPhononContractAddress)
	if err != nil {
		return false, err
	}
	contract := common.HexToAddress(string(contractBytes))

	// Get Bytes Value for ERC721 Token ID then format
	idbytes, err := parsed.FindTag(card.TagPhononContractTokenID)
	if err != nil {
		return false, err
	}

	id, err := util.BytesToFloat32(idbytes)
	if err != nil {
		return false, err
	}

	// Establish Bindings for ERC721 Contract
	erc721Contract, err := erc721.NewErc721(contract, eth.cl)
	if err != nil {
		return false, err
	}

	// Return Actual Owner of Token ID
	owner, err := erc721Contract.OwnerOf(&bind.CallOpts{}, big.NewInt(int64(id)))
	if err != nil {
			return false, errors.New("tagged contract address is not erc721")
	}

	// Check if Phonon Owns Token
	if common.HexToAddress(p.Address) != owner {
		return false, errors.New("erc721 owned by different address:"+owner.String())
	}

	return true, nil
}

func (eth *EthChainService) checkERC20Balance(ctx context.Context, p *model.Phonon) (check bool, err error) {

	packet := tlv.EncodeTLVList(p.ExtendedTLV...)

	// Parse TLV Collection
	parsed, err := tlv.ParseTLVPacket(packet)
	if err != nil {
		return false, err
	}

	// Get Bytes Value for ERC721 Contract Address Tag then format
	contractBytes, err := parsed.FindTag(card.TagPhononContractAddress)
	if err != nil {
		return false, err
	}
	contract := common.HexToAddress(string(contractBytes))

	// Establish Bindings for ERC20 Contract
	erc20Contract, err := erc20.NewErc20(contract, eth.cl)
	if err != nil {
		return false, err
	}

	// Return Actual Balance of ERC20 Token
	balance, err := erc20Contract.BalanceOf(&bind.CallOpts{}, common.HexToAddress(p.Address))
	if err != nil {
			return false, errors.New("tagged contract address is not erc20")
	}

	// Get Phonon Denomination then compare to balance
	denom := new(big.Int).Mul(p.Denomination.Value(), big.NewInt(params.Ether))
	compare := balance.Cmp(denom)

	if compare < 0 {
			return false, errors.New("insufficient balance of erc20")
	}

	return true, nil
}
