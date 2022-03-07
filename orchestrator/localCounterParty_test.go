package orchestrator

import (
	"testing"

	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/session"
	"github.com/GridPlus/phonon-client/util"
)

func TestCardToCardPair(t *testing.T) {
	//Test with real sender and mock receiver card
	cs, err := card.Connect(0)
	if err != nil {
		t.Error(err)
		return
	}
	s, err := session.NewSession(cs)
	if err != nil {
		t.Error(err)
		return
	}
	mockCard, err := card.NewMockCard(true, false)
	if err != nil {
		t.Error(err)
		return
	}

	mockSession, err := session.NewSession(mockCard)
	if err != nil {
		t.Error(err)
		return
	}
	err = mockSession.VerifyPIN("111111")
	if err != nil {
		t.Error(err)
		return
	}
	mockRemote := NewLocalCounterParty(mockSession)

	err = s.VerifyPIN("111111")
	if err != nil {
		t.Error(err)
		return
	}
	err = s.PairWithRemoteCard(mockRemote)
	if err != nil {
		t.Error("error pairing with remote: ", err)
		return
	}
	t.Log("paired local actual card with remote mock")

	//Test with real receiver and mock sender card

	cardAsRemote := NewLocalCounterParty(s)
	err = mockSession.PairWithRemoteCard(cardAsRemote)
	if err != nil {
		t.Error("error pairing mock with remote card: ", err)
		return
	}
	t.Log("paired local mock with remote actual card")
}

//Integration tests that the card actually validates the certificate of it's counterparty during pairing.
func TestCardValidatesCounterpartyCert(t *testing.T) {
	m, _ := card.NewMockCard(false, false)

	signingKey, err := util.ParseECCPrivKey(cert.PhononMockCAPrivKey)
	if err != nil {
		t.Error("error parsing private key. err: ", err)
	}
	testSigner := cert.GetSignerWithPrivateKey(*signingKey)
	_, _, _, err = m.Select()
	if err != nil {
		t.Error(err)
	}

	err = m.InstallCertificate(testSigner)
	if err != nil {
		t.Error("unable to install mock cert")
	}

	err = m.Init("111111")
	if err != nil {
		t.Error(err)
	}
	sender, err := session.NewSession(m)
	if err != nil {
		t.Error(err)
	}

	err = sender.VerifyPIN("111111")
	if err != nil {
		t.Error(err)
	}
	receiverCard, err := card.Connect(0)
	if err != nil {
		t.Error(err)
	}
	receiver, err := session.NewSession(receiverCard)
	if err != nil {
		t.Error(err)
	}
	err = receiver.VerifyPIN("111111")
	if err != nil {
		t.Error(err)
	}

	counterParty := NewLocalCounterParty(receiver)

	err = sender.PairWithRemoteCard(counterParty)
	if err == nil {
		t.Error("pairing mock sender with real receiver should have failed but didn't")
	}
	t.Log("pairing resulted in err: ", err)

	//Try it the other way around, restarting sessions
	mockReceiver, err := session.NewSession(m)
	if err != nil {
		t.Error(err)
	}
	err = mockReceiver.VerifyPIN("111111")
	if err != nil {
		t.Error(err)
	}

	senderCard, err := card.Connect(0)
	if err != nil {
		t.Error(err)
	}
	sender, err = session.NewSession(senderCard)
	if err != nil {
		t.Error(err)
	}
	err = sender.VerifyPIN("111111")
	if err != nil {
		t.Error(err)
	}
	counterParty = NewLocalCounterParty(mockReceiver)

	err = sender.PairWithRemoteCard(counterParty)
	if err == nil {
		t.Error("pairing real sender with mock receiver should have failed but didn't")
	}
	t.Log("pairing real sender with mock receiver resulted in err: ", err)
	//Real cards should not be able to validate this mock in integration tests because they will be installed with the demo or alpha cert

	// privKey, _ := ethcrypto.GenerateKey()
	// fmt.Println("private key: ", util.ECCPrivKeyToHex(privKey))
	// fmt.Println("public key: ", util.ECCPubKeyToHexString(&privKey.PublicKey))
}
