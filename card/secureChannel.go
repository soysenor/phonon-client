package card

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"strings"

	"github.com/GridPlus/keycard-go/apdu"
	"github.com/GridPlus/keycard-go/crypto"
	"github.com/GridPlus/keycard-go/globalplatform"
	"github.com/GridPlus/keycard-go/hexutils"
	"github.com/GridPlus/keycard-go/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)

var ErrInvalidResponseMAC = errors.New("invalid response MAC")

type SecureChannel struct {
	c         types.Channel
	open      bool
	secret    []byte
	publicKey *ecdsa.PublicKey
	encKey    []byte
	macKey    []byte
	iv        []byte
}

func NewSecureChannel(c types.Channel) *SecureChannel {
	return &SecureChannel{
		c: c,
	}
}

func (sc *SecureChannel) GenerateSecret(cardPubKeyData []byte) error {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		return err
	}

	cardPubKey, err := ethcrypto.UnmarshalPubkey(cardPubKeyData)
	if err != nil {
		return err
	}

	sc.publicKey = &key.PublicKey
	sc.secret = crypto.GenerateECDHSharedSecret(key, cardPubKey)

	return nil
}

func (sc *SecureChannel) GenerateStaticSecret(cardPubKeyData []byte) error {
	//Generate a static 40 byte value suitable for generating a predictable key
	var seed string
	for i := 0; i < 40; i++ {
		seed += "A"
	}
	staticSeed := strings.NewReader(seed)
	key, err := ecdsa.GenerateKey(ethcrypto.S256(), staticSeed)
	if err != nil {
		return err
	}
	cardPubKey, err := ethcrypto.UnmarshalPubkey(cardPubKeyData)
	if err != nil {
		return err
	}

	sc.publicKey = &key.PublicKey
	sc.secret = crypto.GenerateECDHSharedSecret(key, cardPubKey)

	return nil
}

func (sc *SecureChannel) Reset() {
	sc.open = false
}

func (sc *SecureChannel) Init(iv, encKey, macKey []byte) {
	sc.iv = iv
	sc.encKey = encKey
	sc.macKey = macKey
	sc.open = true
}

func (sc *SecureChannel) Secret() []byte {
	return sc.secret
}

func (sc *SecureChannel) PublicKey() *ecdsa.PublicKey {
	return sc.publicKey
}

func (sc *SecureChannel) RawPublicKey() []byte {
	return ethcrypto.FromECDSAPub(sc.publicKey)
}

//AES-GCM Symmetric encryption
func (sc *SecureChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	log.Debug("about to send encrypted command: %+v", cmd)
	if sc.open {
		encData, err := crypto.EncryptData(cmd.Data, sc.encKey, sc.iv)
		if err != nil {
			return nil, err
		}

		meta := []byte{cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, byte(len(encData) + 16), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		if err = sc.updateIV(meta, encData); err != nil {
			return nil, err
		}

		newData := append(sc.iv, encData...)
		cmd.Data = newData
	}

	resp, err := sc.c.Send(cmd)
	if err != nil {
		return nil, err
	}

	if resp.Sw != globalplatform.SwOK {
		return nil, apdu.NewErrBadResponse(resp.Sw, "unexpected sw in secure channel")
	}

	rmeta := []byte{byte(len(resp.Data)), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	rmac := resp.Data[:len(sc.iv)]
	rdata := resp.Data[len(sc.iv):]
	plainData, err := crypto.DecryptData(rdata, sc.encKey, sc.iv)
	if err = sc.updateIV(rmeta, rdata); err != nil {
		return nil, err
	}

	if !bytes.Equal(sc.iv, rmac) {
		return nil, ErrInvalidResponseMAC
	}

	log.Debug("apdu response decrypted", "hex", hexutils.BytesToHexWithSpaces(plainData))

	return apdu.ParseResponse(plainData)
}

func (sc *SecureChannel) updateIV(meta, data []byte) error {
	mac, err := crypto.CalculateMac(meta, data, sc.macKey)
	if err != nil {
		return err
	}

	sc.iv = mac

	return nil
}

//TODO: Make sure I can delete this
// func (sc *SecureChannel) OneShotEncrypt(secrets *Secrets) ([]byte, error) {
// 	pubKeyData := ethcrypto.FromECDSAPub(sc.publicKey)
// 	data := append([]byte(secrets.Pin()), []byte(secrets.Puk())...)
// 	data = append(data, secrets.PairingToken()...)

// 	return crypto.OneShotEncrypt(pubKeyData, sc.secret, data)
// }