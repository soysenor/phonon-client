package orchestrator

import (
	"errors"

	"github.com/GridPlus/keycard-go/io"
	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/session"
	"github.com/GridPlus/phonon-client/usb"
)

type PhononTerminal struct {
	sessions []*session.Session
}

type remoteSession struct {
	counterParty model.CounterpartyPhononCard
}

var ErrRemoteNotPaired error = errors.New("no remote card paired")

func (t *PhononTerminal) GenerateMock() error {
	c, err := card.NewMockCard(true, false)
	if err != nil {
		return err
	}
	sess, err := session.NewSession(c)
	if err != nil {
		return err
	}

	t.sessions = append(t.sessions, sess)
	return nil
}

func (t *PhononTerminal) RefreshSessions() ([]*session.Session, error) {
	t.sessions = nil
	var err error
	readers, err := usb.ConnectAllUSBReaders()
	if err != nil {
		return nil, err
	}
	for _, reader := range readers {
		session, err := session.NewSession(card.NewPhononCommandSet(io.NewNormalChannel(reader)))
		if err != nil {
			return nil, err
		}
		t.sessions = append(t.sessions, session)
	}
	if len(t.sessions) == 0 {
		return nil, errors.New("no cards detected")
	}
	return t.sessions, nil
}

// func (t *PhononTerminal) InitializePin(sessionIndex int, pin string) error {
// 	err := t.sessions[sessionIndex].Init(pin)
// 	return err
// }

func (t *PhononTerminal) ListSessions() []*session.Session {
	return t.sessions
}

func (t *PhononTerminal) SetReceiveMode(sessionIndex int) {
	// set this session to accept incoming secureConnections
}
