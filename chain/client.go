package chain

import (
	"errors"
	"github.com/GridPlus/phonon-client/model"
)

type BlockchainClient struct {
}

var ErrMissingPubKey = errors.New("phonon missing pubKey")
var ErrMissingKeyIndex = errors.New("phonon missing KeyIndex")

func DepositToPhonons(phonons []*model.Phonon) error {
	//validate data
	for _, p := range phonons {
		if p.PubKey == nil {
			return ErrMissingPubKey
		}
		if p.KeyIndex == 0 {
			return ErrMissingKeyIndex
		}
	}
	//Submit on chain transaction

	//Check for confirmation
	return nil
}
