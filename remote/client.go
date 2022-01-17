package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/session"
	"github.com/GridPlus/phonon-client/util"
	"github.com/posener/h2conn"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

type RemoteConnection struct {
	conn                     *h2conn.Conn
	out                      *gob.Encoder
	in                       *gob.Decoder
	remoteCertificate        *cert.CardCertificate
	session                  *session.Session
	identifiedWithServerChan chan bool
	identifiedWithServer     bool
	counterpartyNonce        [32]byte
	verified                 bool
	connectedToCardChan      chan bool
	pairFinalized            bool
	verifyPairedChan         chan string

	//card pairing message channels
	remoteCertificateChan    chan cert.CardCertificate
	remoteIdentityChan       chan []byte
	cardPair1DataChan        chan []byte
	finalizeCardPairDataChan chan []byte
	pairingStatus            model.RemotePairingStatus

	phononAckChan chan bool
}

// this will go someplace, I swear
var ErrTimeout = errors.New("Timeout")

func Connect(s *session.Session, url string, ignoreTLS bool) (*RemoteConnection, error) {
	d := &h2conn.Client{
		Client: &http.Client{
			Transport: &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: ignoreTLS}},
		},
	}

	conn, resp, err := d.Connect(context.Background(), url) //url)
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to remote server %e,", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Error("received bad status from jumpbox. err: ", resp.Status)
	}

	client := &RemoteConnection{
		session: s,
		conn:    conn,
		out:     gob.NewEncoder(conn),
		in:      gob.NewDecoder(conn),
		//initialize connection channels
		connectedToCardChan:      make(chan bool, 1),
		identifiedWithServerChan: make(chan bool, 1),
		//initialize card pairing channels
		remoteCertificateChan:    make(chan cert.CardCertificate, 1),
		remoteIdentityChan:       make(chan []byte, 1),
		cardPair1DataChan:        make(chan []byte, 1),
		finalizeCardPairDataChan: make(chan []byte, 1),

		phononAckChan: make(chan bool, 1),

		pairingStatus: model.StatusConnectedToBridge,
	}

	//First send the client cert to kick off connection validation
	if s.Cert == nil {
		s.Cert, err = s.GetCertificate()
		if err != nil {
			log.Error("could not fetch certificate from card: ", err)
			return nil, err
		}
	}
	log.Info("client has crt: ", s.Cert)
	err = client.out.Encode(s.Cert.Serialize())
	if err != nil {
		log.Error("unable to send cert to jump server. err: ", err)
		return nil, err
	}
	//TODO: remove or debug
	log.Info("got past first encode")

	go client.HandleIncoming()

	return client, nil
}

func (c *RemoteConnection) HandleIncoming() {
	message := Message{}
	err := c.in.Decode(&message)
	for err == nil {
		c.process(message)
		message := Message{}
		err = c.in.Decode(&message)
	}
	log.Printf("Error decoding message: %s", err.Error())
	c.pairingStatus = model.StatusUnconnected
}

func (c *RemoteConnection) process(msg Message) {
	switch msg.Name {
	case RequestCertificate:
		c.sendCertificate(msg)
	case ResponseCertificate:
		c.receiveCertificate(msg)
	case RequestIdentify:
		c.sendIdentify(msg)
	case ResponseIdentify:
		c.processIdentify(msg)
	case MessageError:
		log.Error(string(msg.Payload))
	case MessageIdentifiedWithServer:
		c.identifiedWithServerChan <- true
		c.identifiedWithServer = true
	case MessageConnectedToCard:
		c.pairingStatus = model.StatusConnectedToCard
	// Card pairing requests and responses
	case RequestCardPair1:
		c.processCardPair1(msg)
	case ResponseCardPair1:
		c.cardPair1DataChan <- msg.Payload
	case RequestFinalizeCardPair:
		c.processFinalizeCardPair(msg)
	case ResponseFinalizeCardPair:
		c.finalizeCardPairDataChan <- msg.Payload
	case MessagePhononAck:
		c.phononAckChan <- true
	case RequestReceivePhonon:
		c.processReceivePhonons(msg)
	case RequestVerifyPaired:
		c.processRequestVerifyPaired(msg)
	case MessageDisconnected:
		c.disconnect()
	case RequestDisconnectFromCard:
		c.disconnectFromCard()
	case ResponseVerifyPaired:
		{
			if c.verifyPairedChan != nil {
				c.verifyPairedChan <- string(msg.Payload)
			}
		}
	}
}

/////
// Below are the request processing methods
/////

func (c *RemoteConnection) sendCertificate(msg Message) {
	cert, err := c.session.GetCertificate()
	if err != nil {
		log.Error("Cert doesn't exist")
	}
	c.sendMessage(ResponseCertificate, cert.Serialize())
}

func (c *RemoteConnection) sendIdentify(msg Message) {
	_, sig, err := c.session.IdentifyCard(msg.Payload)
	if err != nil {
		log.Error("Issue identifying local card", err.Error())
		return
	}
	payload := []byte{}
	buf := bytes.NewBuffer(payload)
	enc := gob.NewEncoder(buf)
	enc.Encode(sig)
	c.sendMessage(ResponseIdentify, buf.Bytes())
}

func (c *RemoteConnection) processIdentify(msg Message) {
	key, sig, err := card.ParseIdentifyCardResponse(msg.Payload)
	if err != nil {
		log.Error("Issue parsing identify card response", err.Error())
		return
	}
	if !ecdsa.Verify(key, c.counterpartyNonce[:], sig.R, sig.S) {
		log.Error("Unable to verify card challenge")
		return
	} else {
		c.verified = true
		return
	}
}

func (c *RemoteConnection) processCardPair1(msg Message) {
	if c.pairingStatus != model.StatusConnectedToCard {
		log.Error("Card either not connected to a card or already paired")
		return
	}
	cardPairData, err := c.session.CardPair(msg.Payload)
	if err != nil {
		log.Error("error with card pair 1", err.Error())
		return
	}
	c.pairingStatus = model.StatusCardPair1Complete
	c.sendMessage(ResponseCardPair1, cardPairData)

}

func (c *RemoteConnection) processFinalizeCardPair(msg Message) {
	if c.pairingStatus != model.StatusCardPair1Complete {
		log.Error("Unable to pair. Step one not complete")
		return
	}
	err := c.session.FinalizeCardPair(msg.Payload)
	if err != nil {
		log.Error("Error finalizing Card Pair", err.Error())
		c.sendMessage(ResponseFinalizeCardPair, []byte(err.Error()))
		return
	}
	c.sendMessage(ResponseFinalizeCardPair, []byte{})
	c.pairFinalized = true
	c.pairingStatus = model.StatusPaired
	c.session.RemoteCard = c
	//c.finalizeCardPairErrorChan <- err
}

func (c *RemoteConnection) processReceivePhonons(msg Message) {
	// would check for status to be paired, but for replayability, I'm not entirely sure this is necessary
	err := c.session.ReceivePhonons(msg.Payload)
	if err != nil {
		log.Error(err.Error())
		return
	}
	c.sendMessage(MessagePhononAck, []byte{})
}

// ProcessProvideCertificate is for adding a remote card's certificate to the remote portion of the struct
func (c *RemoteConnection) receiveCertificate(msg Message) {
	remoteCert, err := cert.ParseRawCardCertificate(msg.Payload)
	if err != nil {
		log.Error(err)
		return
	}
	c.remoteCertificateChan <- remoteCert
	c.remoteCertificate = &remoteCert
}

/////
// Below are the methods that satisfy the interface for remote counterparty
/////
func (c *RemoteConnection) Identify() error {
	var nonce [32]byte
	rand.Read(nonce[:])
	c.counterpartyNonce = nonce
	c.sendMessage(RequestIdentify, nonce[:])
	select {
	case <-c.remoteIdentityChan:
		return nil
	case <-time.After(10 * time.Second):
		return ErrTimeout

	}
}

func (c *RemoteConnection) CardPair(initPairingData []byte) (cardPairData []byte, err error) {
	c.sendMessage(RequestCardPair1, initPairingData)
	select {
	case cardPairData := <-c.cardPair1DataChan:
		return cardPairData, nil
	case <-time.After(10 * time.Second):
		return []byte{}, ErrTimeout
	}
}

func (c *RemoteConnection) CardPair2(cardPairData []byte) (cardPairData2 []byte, err error) {
	//unneeded
	return []byte{}, nil
}

func (c *RemoteConnection) FinalizeCardPair(cardPair2Data []byte) error {
	c.sendMessage(RequestFinalizeCardPair, cardPair2Data)
	if !c.pairFinalized {
		select {
		case errorbytes := <-c.finalizeCardPairDataChan:
			var err error
			if len(errorbytes) > 0 {
				return errors.New(string(errorbytes))
			} else {
				return err
			}
		case <-time.After(10 * time.Second):
			return ErrTimeout
		}
	}
	c.pairFinalized = true
	c.session.RemoteCard = c
	return nil
}

func (c *RemoteConnection) GetCertificate() (*cert.CardCertificate, error) {
	if c.remoteCertificate == nil {
		c.sendMessage(RequestCertificate, []byte{})
		select {
		case cert := <-c.remoteCertificateChan:
			c.remoteCertificate = &cert
		case <-time.After(10 * time.Second):
			return nil, ErrTimeout
		}

	}
	return c.remoteCertificate, nil
}

func (c *RemoteConnection) ConnectToCard(cardID string) error {
	if !c.identifiedWithServer {
		select {
		case <-time.After(10 * time.Second):
			return ErrTimeout
		case <-c.identifiedWithServerChan:
			log.Info("received Identified with server")
		}
	}
	log.Info("sending requestConnectCard2Card message")
	err := c.out.Encode(Message{Name: RequestConnectCard2Card, Payload: []byte(cardID)})
	if err != nil {
		log.Error("error sending Connect2Card request to jumpbox: ", err)
		return err
	}
	return nil
}

func (c *RemoteConnection) ReceivePhonons(PhononTransfer []byte) error {
	c.sendMessage(RequestReceivePhonon, PhononTransfer)
	select {
	case <-time.After(10 * time.Second):
		log.Error("unable to verify remote recipt of phonons")
		return ErrTimeout
	case <-c.phononAckChan:
		return nil
	}
}

func (c *RemoteConnection) GenerateInvoice() (invoiceData []byte, err error) {
	// todo:
	return
}

func (c *RemoteConnection) ReceiveInvoice(invoiceData []byte) error {
	// todo:
	return nil
}

// Utility functions
func (c *RemoteConnection) sendMessage(messageName string, messagePayload []byte) {
	log.Debug(messageName, string(messagePayload))

	tosend := &Message{
		Name:    messageName,
		Payload: messagePayload,
	}
	c.out.Encode(tosend)
}

func (c *RemoteConnection) VerifyPaired() error {
	tosend := &Message{
		Name:    RequestVerifyPaired,
		Payload: []byte(""),
	}
	c.verifyPairedChan = make(chan string)
	c.out.Encode(tosend)

	var connectedCardID string
	select {
	case connectedCardID = <-c.verifyPairedChan:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("counterparty card not paired to this card")
	}
	c.verifyPairedChan = nil

	var err error
	if connectedCardID != c.session.GetName() {
		//remote isn't paired to this card
		err = c.session.PairWithRemoteCard(c)
	}
	return err
}

func (c *RemoteConnection) processRequestVerifyPaired(msg Message) {
	tosend := &Message{
		Name: ResponseVerifyPaired,
	}
	if c.pairFinalized {
		key, err := util.ParseECDSAPubKey(c.remoteCertificate.PubKey)
		if err != nil {
			//oopsie
			return
		}
		msg := util.ECDSAPubKeyToHexString(key)[:16]
		tosend.Payload = []byte(msg)
	}
	c.out.Encode(tosend)
}

func (c *RemoteConnection) PairingStatus() model.RemotePairingStatus {
	return c.pairingStatus
}

func (c *RemoteConnection) disconnect() {
	c.pairingStatus = model.StatusUnconnected
	c.session.SetPaired(false)
}

func (c *RemoteConnection) disconnectFromCard() {
	c.pairingStatus = model.StatusConnectedToBridge
	c.session.SetPaired(false)
}
