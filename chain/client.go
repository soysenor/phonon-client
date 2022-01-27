package chain

import (
	"errors"
	"github.com/GridPlus/phonon-client/model"
	"github.com/ethereum/go-ethereum/core/types"
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

/*CreateDepositTransaction takes a list of phonons and forms a transaction to deposit assets into them
on the specified chain*/
func CreateDepositTransaction(phonons *model.Phonon) ([]byte, error) {
	types.TxData{}
	types.NewTx()

}
