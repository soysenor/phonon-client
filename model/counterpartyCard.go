package model

import (
	"github.com/GridPlus/phonon-client/cert"
)

type CounterpartyPhononCard interface {
	GetCertificate() (*cert.CardCertificate, error)
	CardPair(initPairingData []byte) (cardPairData []byte, err error)
	CardPair2(cardPairData []byte) (cardPairData2 []byte, err error)
	FinalizeCardPair(cardPair2Data []byte) error
	ReceivePhonons(phononTransfer []byte) error
	GenerateInvoice() (invoiceData []byte, err error)
	ReceiveInvoice(invoiceData []byte) error
	VerifyPaired() error
	PairingStatus() RemotePairingStatus
	ConnectToCard(string) error
}

type RemotePairingStatus int

const (
	StatusUnconnected RemotePairingStatus = iota
	StatusConnectedToBridge
	StatusConnectedToCard
	StatusPaired
	StatusCardPair1Complete
	StatusCardPair2Complete
)

type Message struct {
	Name    string
	Payload []byte
}

var (
	// Server to client messages
	MessageConnected            = "Connected"
	MessageDisconnected         = "Disconnected"
	MessageError                = "Error"
	MessagePassthruFailed       = "PassthruFailed"
	MessageIdentifiedWithServer = "IdentifiedWithServer"
	MessageConnectedToCard      = "connectedToCard"

	// Client to server commands
	RequestIdentify           = "Identify"
	ResponseIdentify          = "IdentifyResponse"
	RequestCertificate        = "RequestCert"
	ResponseCertificate       = "ResponseCert"
	RequestNoOp               = "NoOp"
	RequestConnectCard2Card   = "Connect2Card"
	RequestDisconnectFromCard = "DisconnectFromCard"
	RequestEndSession         = "EndSession"
	MessagePhononAck          = "AckPhonon"

	// Client to client commands
	RequestVerifyPaired      = "VerifyPairing"
	ResponseVerifyPaired     = "VerifyPairingRespnose"
	RequestCardPair1         = "CardPair1"
	ResponseCardPair1        = "CardPair1Response"
	RequestCardPair2         = "CardPair2"
	ResponseCardPair2        = "CardPair2Response"
	RequestFinalizeCardPair  = "FinalizeCardPair"
	ResponseFinalizeCardPair = "FinalizeCardPairResponse"
	// this one is weird because the server will cache this one
	RequestReceivePhonon = "requestReceivePhonon"
)
