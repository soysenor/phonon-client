package card

import (
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/model"
)

func TestCardPair(t *testing.T) {
	senderCard, err := NewMockCard(false, false)
	if err != nil {
		t.Error(err)
	}

	err = senderCard.InstallCertificate(cert.SignWithDemoKey)
	if err != nil {
		t.Error(err)
	}

	receiverCard, err := NewMockCard(false, false)
	if err != nil {
		t.Error(err)
	}
	err = receiverCard.InstallCertificate(cert.SignWithDemoKey)
	if err != nil {
		t.Error(err)
	}

	initPairingData, err := senderCard.InitCardPairing(receiverCard.IdentityCert)
	if err != nil {
		t.Error("error in initCardPairing")
		t.Error(err)
	}
	_, err = receiverCard.CardPair(initPairingData)
	if err != nil {
		t.Error("error in card pair")
		t.Error(err)
	}
}

func TestCreatePostedPhonons(t *testing.T) {
	card, err := NewMockCard(true, false)
	if err != nil {
		t.Error(err)
	}

	card.VerifyPIN("111111")

	keyIndex, pubKey, err := card.CreatePhonon(model.Secp256k1)

	if err != nil {
		t.Error(err)
	}

	if keyIndex != 0 {
		t.Error("keyIndex is not 0;", keyIndex)
	}

	if pubKey == nil {
		t.Error("pubKey is nil", pubKey)
	}

	result, err := card.SendPostedPhonons("abc123", 1, []uint16{1})

	if err != nil {
		t.Error(err)
	}

	log.Debug(result)
}
