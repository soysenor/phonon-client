package remote

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"net/http"

	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/util"
	"github.com/posener/h2conn"
	log "github.com/sirupsen/logrus"
)

func StartServer(port string, certfile string, keyfile string) {
	//init sessions global
	clientSessions = make(map[string]*clientSession)
	http.HandleFunc("/phonon", handle)
	http.HandleFunc("/connected", listConnected)
	http.HandleFunc("/", index)
	err := http.ListenAndServeTLS(":"+port, certfile, keyfile, nil)
	if err != nil {
		log.Errorf("Error with web server:, %s", err.Error())
	}
}

type clientSession struct {
	Name           string
	certificate    *cert.CardCertificate
	challengeNonce [32]byte
	underlyingConn *h2conn.Conn
	sender         *gob.Encoder
	receiver       *gob.Decoder
	validated      bool
	end            chan bool
	Counterparty   *clientSession
	// the same name that goes in the lookup value of the clientSession map
	name string
}

var clientSessions map[string]*clientSession

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello there"))
}

func listConnected(w http.ResponseWriter, r *http.Request) {
	ret, _ := json.Marshal(clientSessions)
	w.Write(ret)
}

func handle(w http.ResponseWriter, r *http.Request) {
	conn, err := h2conn.Accept(w, r)
	if err != nil {
		log.Debug("Unable to establish http2 duplex connection with ", r.RemoteAddr)
		//status teapot is obviously wrong here. need to research what causes this error and return a proper response
		http.Error(w, "Unable to establish duplex connection between server and client", http.StatusTeapot)
	}
	cmdEncoder := gob.NewEncoder(conn)
	cmdDecoder := gob.NewDecoder(conn)
	//generate session
	session := clientSession{
		sender:   cmdEncoder,
		receiver: cmdDecoder,
		end:      make(chan (bool)),
	}

	messageChan := make(chan (Message))

	go func(msgchan chan Message) {
		defer close(msgchan)
		for {
			message := Message{}
			err := session.receiver.Decode(&message)
			if err != nil {
				log.Info("Error receiving message from connected client")
				session.endSession(Message{"", []byte("")})
				return
			}
			msgchan <- message
		}
	}(messageChan)

	newMessage := Message{
		Name: RequestCertificate,
	}

	cmdEncoder.Encode(newMessage)

	for message := range messageChan {
		session.process(message)
	}
	conn.Close()

	//ask connected card for a certificate and send challenge
	//when certificate is verified, add to list of connected cards
	//process messages
}

func (c *clientSession) process(msg Message) {
	log.Infof("processing message: %s\nPayload: %+v\nPayloadString: %s\n", msg.Name, msg.Payload, string(msg.Payload))
	// if the client hasn't identified itself with the server, ignore what they are doing until they provide the certificate, and keep asking for it.
	if c.certificate == nil {
		// if they are providing the certificate, accept it, and then generate a challenge, add it to the challenge test, and continue executing
		if msg.Name == ResponseCertificate {
			certParsed, err := cert.ParseRawCardCertificate(msg.Payload)
			if err != nil {
				log.Infof("failed to parse certificate from client %s\n", err.Error())
				return
			}
			c.certificate = &certParsed
		} else {
			//ask for the certificate again
			c.sender.Encode(Message{
				Name: RequestCertificate,
			})
			return
		}
	}

	if !c.validated {
		if msg.Name == ResponseIdentify {
			buf := bytes.NewBuffer(msg.Payload)
			decoder := gob.NewDecoder(buf)
			var sig = &util.ECDSASignature{}
			err := decoder.Decode(sig)
			if err != nil {
				log.Error("Unable to parse IdentifyCardResponse", err.Error())
				return
			}
			key, err := util.ParseECDSAPubKey(c.certificate.PubKey)
			if err != nil {
				log.Error("Unable to parse pubkey from certificate", err.Error())
				return
			}
			if !ecdsa.Verify(key, c.challengeNonce[:], sig.R, sig.S) {
				log.Error("unable to verify card challenge")
				return
			}
			c.validated = true
			//todo: get the short name the same way it works in the repl
			hexString := util.ECDSAPubKeyToHexString(key)
			name := hexString[:16]
			c.Name = name
			clientSessions[name] = c
			c.sender.Encode(Message{
				Name:    MessageIdentifiedWithServer,
				Payload: []byte(name),
			})
			return
		} else {
			if c.challengeNonce == [32]byte{} {
				_, err := rand.Reader.Read(c.challengeNonce[:])
				if err != nil {
					log.Errorf("Error generating challenge: %s", err.Error())
					return
				}
			}
			c.RequestIdentify()
			return
		}
		// if the challenge text has been set, ignore what they want and send it again
	}
	switch msg.Name {
	case RequestConnectCard2Card:
		c.ConnectCard2Card(msg)
	case RequestDisconnectFromCard:
		c.disconnectFromCard(msg)
	case RequestEndSession:
		c.endSession(msg)
	case RequestNoOp:
		c.noop(msg)
	case ResponseIdentify, RequestCardPair1, ResponseCardPair1, RequestCardPair2, ResponseCardPair2, RequestFinalizeCardPair, ResponseFinalizeCardPair, RequestReceivePhonon, MessagePhononAck:
		c.passthrough(msg)
	case RequestCertificate:
		c.provideCertificate()
	}
}

func (c *clientSession) RequestIdentify() {
	c.sender.Encode(Message{
		Name:    RequestIdentify,
		Payload: c.challengeNonce[:],
	})
}

func (c *clientSession) provideCertificate() {
	if c.Counterparty == nil {
		c.sender.Encode(Message{
			Name:    MessageError,
			Payload: []byte("No counterparty connected. Cannot get certificate"),
		})
		return
	}
	msg := Message{
		Name:    ResponseCertificate,
		Payload: c.Counterparty.certificate.Serialize(),
	}
	err := c.sender.Encode(msg)
	if err != nil {
		log.Error("Error encoding provideCertificate reply: ", err)
		return
	}
	return
}

func (c *clientSession) ConnectCard2Card(msg Message) {
	log.Infof("attempting to connect card %s to card %s\n", c.Name, string(msg.Payload))
	counterparty, ok := clientSessions[string(msg.Payload)]
	if !ok {
		c.sender.Encode(Message{
			Name:    MessageError,
			Payload: []byte("No connected card"),
		})
		log.Error("No connected session:", string(msg.Payload))
		return
	} else if counterparty.Counterparty == nil && c.Counterparty == nil {
		counterparty.Counterparty = c
		c.Counterparty = counterparty
		c.sender.Encode(Message{
			Name: MessageConnectedToCard,
		})
		c.Counterparty.sender.Encode(Message{
			Name: MessageConnectedToCard,
		})
	} else if c.Counterparty == counterparty && counterparty.Counterparty == c {
		//do nothing
	} else {
		c.sender.Encode(Message{
			Name:    MessageError,
			Payload: []byte("Unable to connect. Connection already satisfied"),
		})
	}
}

func (c *clientSession) disconnectFromCard(msg Message) {
	out := Message{
		Name: MessageDisconnected,
	}
	// encode can fail, so it needs to be checked. Not sure how to handle that
	if c.Counterparty.sender != nil {
		c.Counterparty.sender.Encode(out)
	}
	if c.sender != nil {
		c.sender.Encode(out)
	}
	if c.Counterparty != nil {
		c.Counterparty.Counterparty = nil
	}
	c.Counterparty = nil
}

func (c *clientSession) endSession(msg Message) {
	c.disconnectFromCard(msg)
	delete(clientSessions, c.Name)
	if c.underlyingConn != nil {
		c.underlyingConn.Close()
	}
}

func (c *clientSession) noop(msg Message) {
	// don't do anything
	// this is eventually going to be for preventing connection timeouts, but may not be nessesary in the future
}

func (c *clientSession) passthrough(msg Message) {
	if c.Counterparty == nil {
		ret := Message{
			Name: MessagePassthruFailed,
		}
		c.sender.Encode(ret)
		return
	}
	c.Counterparty.sender.Encode(msg)
	// needs error handling on the encoding
}

func (c *clientSession) RequestSendPhonon(msg Message) {

}

func (c *clientSession) RequestPhononAck(msg Message) {

}

func (c *clientSession) sendPhonon(msg Message) {
	// save this packet for later
	// delete after ack
}

func (c *clientSession) ack(msg Message) {
	// delete saved phonon when received
}
