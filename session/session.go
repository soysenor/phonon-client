package session

import (
	"crypto/ecdsa"
	"errors"

	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/chain"
	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"

	log "github.com/sirupsen/logrus"
)

/*The session struct handles a local connection with a card
Keeps a client side cache of the card state to make interaction
with the card through this API more convenient*/
type Session struct {
	cs             model.PhononCard
	RemoteCard     model.CounterpartyPhononCard
	identityPubKey *ecdsa.PublicKey
	active         bool
	pinInitialized bool
	terminalPaired bool
	pinVerified    bool
	Cert           *cert.CardCertificate
	name           string
}

var ErrAlreadyInitialized = errors.New("card is already initialized with a pin")
var ErrInitFailed = errors.New("card failed initialized check after init command accepted")
var ErrCardNotPairedToCard = errors.New("card not paired with any other card")

//Creates a new card session, automatically connecting if the card is already initialized with a PIN
//The next step is to run VerifyPIN to gain access to the secure commands on the card
func NewSession(storage model.PhononCard) (s *Session, err error) {
	s = &Session{
		cs:             storage,
		active:         true,
		terminalPaired: false,
		pinVerified:    false,
	}
	_, _, s.pinInitialized, err = s.cs.Select()
	if err != nil {
		log.Error("cannot select card for new session: ", err)
		return nil, err
	}
	if !s.pinInitialized {
		return s, nil
	}
	//If card is already initialized, go ahead and open terminal to card secure channel
	err = s.Connect()
	if err != nil {
		log.Error("could not run session connect: ", err)
		return nil, err
	}

	return s, nil
}

func (s *Session) SetPaired(status bool) {
}

func (s *Session) GetName() string {
	if s.Cert == nil {
		return "unknown"
	}
	if s.Cert.PubKey != nil {
		hexString := util.ECCPubKeyToHexString(s.identityPubKey)
		if len(hexString) >= 16 {
			return hexString[:16]
		}
	}
	return "unknown"
}

func (s *Session) GetCertificate() (*cert.CardCertificate, error) {
	if s.Cert != nil {
		log.Debugf("GetCertificate returning cert: % X", s.Cert)
		return s.Cert, nil
	}

	return &cert.CardCertificate{}, errors.New("certificate not cached by session yet")
}

func (s *Session) IsUnlocked() bool {
	return s.pinVerified
}

func (s *Session) IsInitialized() bool {
	return s.pinInitialized
}

func (s *Session) IsPairedToCard() bool {
	return s.RemoteCard != nil
}

//Connect opens a secure channel with a card.
func (s *Session) Connect() error {
	cert, err := s.cs.Pair()
	if err != nil {
		return err
	}
	s.Cert = cert
	s.identityPubKey, _ = util.ParseECCPubKey(s.Cert.PubKey)
	err = s.cs.OpenSecureChannel()
	if err != nil {
		return err
	}
	s.terminalPaired = true
	return nil
}

//Initializes the card with a PIN
//Also creates a secure channel and verifies the PIN that was just set
func (s *Session) Init(pin string) error {
	if s.pinInitialized {
		return ErrAlreadyInitialized
	}
	err := s.cs.Init(pin)
	if err != nil {
		return err
	}
	s.pinInitialized = true
	//Open new secure connection now that card is initialized
	err = s.Connect()
	if err != nil {
		return err
	}
	s.pinVerified = true

	return nil
}

func (s *Session) VerifyPIN(pin string) error {
	err := s.cs.VerifyPIN(pin)
	if err != nil {
		return err
	}
	s.pinVerified = true
	return nil
}

func (s *Session) ChangePIN(pin string) error {
	if !s.pinVerified {
		return errors.New("card locked, cannot change pin")
	}
	return s.cs.ChangePIN(pin)
}

func (s *Session) verified() bool {
	if s.pinVerified && s.terminalPaired {
		return true
	}
	return false
}

func (s *Session) CreatePhonon() (keyIndex uint16, pubkey *ecdsa.PublicKey, err error) {
	if !s.verified() {
		return 0, nil, card.ErrPINNotEntered
	}
	return s.cs.CreatePhonon(model.Secp256k1)
}

func (s *Session) SetDescriptor(p *model.Phonon) error {
	if !s.verified() {
		return card.ErrPINNotEntered
	}
	return s.cs.SetDescriptor(p)
}

func (s *Session) ListPhonons(currencyType model.CurrencyType, lessThanValue uint64, greaterThanValue uint64) ([]*model.Phonon, error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	return s.cs.ListPhonons(currencyType, lessThanValue, greaterThanValue)
}

func (s *Session) GetPhononPubKey(keyIndex uint16) (pubkey *ecdsa.PublicKey, err error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	return s.cs.GetPhononPubKey(keyIndex)
}

func (s *Session) DestroyPhonon(keyIndex uint16) (privKey *ecdsa.PrivateKey, err error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	return s.cs.DestroyPhonon(keyIndex)
}

func (s *Session) IdentifyCard(nonce []byte) (cardPubKey *ecdsa.PublicKey, cardSig *util.ECDSASignature, err error) {
	return s.cs.IdentifyCard(nonce)
}

func (s *Session) InitCardPairing(receiverCert cert.CardCertificate) ([]byte, error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	return s.cs.InitCardPairing(receiverCert)
}

func (s *Session) CardPair(initPairingData []byte) ([]byte, error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	return s.cs.CardPair(initPairingData)
}

func (s *Session) CardPair2(cardPairData []byte) (cardPair2Data []byte, err error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	cardPair2Data, err = s.cs.CardPair2(cardPairData)
	if err != nil {
		return nil, err
	}
	log.Debug("set card session paired")
	return cardPair2Data, nil
}

func (s *Session) FinalizeCardPair(cardPair2Data []byte) error {
	if !s.verified() {
		return card.ErrPINNotEntered
	}
	err := s.cs.FinalizeCardPair(cardPair2Data)
	if err != nil {
		return err
	}
	return nil
}

//Keeping this around for now in case we need a version that does not interact with remote
// func (s *Session) SendPhonons(keyIndices []uint16) ([]byte, error) {
// 	if !s.verified() && s.RemoteCard != nil {
// 		return nil, ErrCardNotPairedToCard
// 	}
// 	phononTransferPacket, err := s.cs.SendPhonons(keyIndices, false)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return phononTransferPacket, nil
// }

func (s *Session) SendPhonons(keyIndices []uint16) error {
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}
	phononTransferPacket, err := s.cs.SendPhonons(keyIndices, false)
	if err != nil {
		return err
	}
	err = s.RemoteCard.ReceivePhonons(phononTransferPacket)
	if err != nil {
		log.Debug("error receiving phonons on remote")
		return err
	}
	return nil
}

func (s *Session) ReceivePhonons(phononTransferPacket []byte) error {
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}
	err := s.cs.ReceivePhonons(phononTransferPacket)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) GenerateInvoice() ([]byte, error) {
	if !s.verified() && s.RemoteCard != nil {
		return nil, ErrCardNotPairedToCard
	}
	return s.cs.GenerateInvoice()
}

func (s *Session) ReceiveInvoice(invoiceData []byte) error {
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}
	err := s.cs.ReceiveInvoice(invoiceData)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) PairWithRemoteCard(remoteCard model.CounterpartyPhononCard) error {
	remoteCert, err := remoteCard.GetCertificate()
	if err != nil {
		return err
	}
	initPairingData, err := s.InitCardPairing(*remoteCert)
	if err != nil {
		return err
	}
	cardPairData, err := remoteCard.CardPair(initPairingData)
	if err != nil {
		return err
	}
	cardPair2Data, err := s.CardPair2(cardPairData)
	if err != nil {
		return err
	}
	err = remoteCard.FinalizeCardPair(cardPair2Data)
	if err != nil {
		return err
	}
	s.RemoteCard = remoteCard
	return nil
}

/*DepositPhonons takes a currencyType and a map of denominations to quantity,
Creates the required phonons, deposits them using the configured service for the asset
and upon success sets their descriptors*/
func (s *Session) DepositPhonons(currencyType model.CurrencyType, denoms []model.Denomination) (phonons []*model.Phonon, err error) {

	for _, denom := range denoms {
		p := &model.Phonon{}
		p.KeyIndex, p.PubKey, err = s.CreatePhonon()
		if err != nil {
			return nil, err
		}
		p.Denomination = denom
		p.CurrencyType = currencyType
		phonons = append(phonons, p)
	}
	err = chain.DepositToPhonons(phonons)
	if err != nil {
		//If deposit fails, cleanup phonons that weren't able to be encumbered on chain
		for _, p := range phonons {
			_, err := s.DestroyPhonon(p.KeyIndex)
			if err != nil {
				log.Error("unable to destroy unconfirmed phonon at KeyIndex %v. err: ", p.KeyIndex, err)
			}
		}
		return nil, err
	}
	for _, p := range phonons {
		err = s.SetDescriptor(p)
		if err != nil {
			//TODO: work out what to do in the event that only some descriptors fail
			log.Error("unable to set descriptor on deposited phonon at KeyIndex: %v. err: ", p.KeyIndex, err)
		}
	}
	return phonons, nil
}
