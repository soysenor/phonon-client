package repl

import (
	"math/big"
	"strconv"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"
	ishell "github.com/abiosoft/ishell/v2"
)

func createPhonon(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	keyIndex, pubKey, err := activeCard.CreatePhonon()
	if err != nil {
		c.Println("error creating phonon: ", err)
		return
	}
	c.Println("created phonon")
	c.Println("Key Index: ", keyIndex)
	c.Println("Public Key: ", util.ECCPubKeyToHexString(pubKey))
}

func listPhonons(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	var currencyType model.CurrencyType = 0
	var lessThanValue uint64
	var greaterThanValue uint64
	var numCorrectArgs = 3

	if len(c.Args) == numCorrectArgs {
		currencyTypeInt, err := strconv.ParseInt(c.Args[0], 10, 0)
		if err != nil {
			c.Println("error parsing currencyType: ", err)
			return
		}
		currencyType = model.CurrencyType(currencyTypeInt)

		//uint64 parsing
		lessThanValue, err = strconv.ParseUint(c.Args[1], 10, 0)
		if err != nil {
			c.Println("error parsing lessThanValue: ", err)
			return
		}
		greaterThanValue, err = strconv.ParseUint(c.Args[1], 10, 0)
		if err != nil {
			c.Println("error parsing greaterThanValue: ", err)
			return
		}

	}
	phonons, err := activeCard.ListPhonons(currencyType, lessThanValue, greaterThanValue)
	if err != nil {
		c.Println("error listing phonons: ", err)
		return
	}
	for _, p := range phonons {
		p.PubKey, err = activeCard.GetPhononPubKey(p.KeyIndex)
		if err != nil {
			c.Printf("error retrieving phonon pubKey at keyIndex %v. err: %v\n", p.KeyIndex, err)
		}
	}
	c.Println("phonons: ")
	for _, p := range phonons {
		c.Printf("%v\n", p)
		test, err := p.MarshalJSON()
		if err != nil {
			c.Printf("error marshaling", err)
			c.Printf("%v\n", test)
		}
	}
}

func setDescriptor(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	numCorrectArgs := 4
	if len(c.Args) != numCorrectArgs {
		c.Printf("setDescriptor requires %v args\n", numCorrectArgs)
		return
	}

	keyIndex, err := strconv.ParseUint(c.Args[0], 10, 16)
	if err != nil {
		c.Println("keyIndex could not be parsed: ", err)
		return
	}
	currencyTypeInt, err := strconv.Atoi(c.Args[1])
	if err != nil {
		c.Println("currencyType could not be parse: ", err)
		return
	}
	currencyType := model.CurrencyType(currencyTypeInt)

	value, err := strconv.ParseUint(c.Args[2], 10, 0)
	if err != nil {
		c.Println("value could not be parse: ", err)
		return
	}
	denomination, err := model.NewDenomination(big.NewInt(int64(value)))
	if err != nil {
		c.Println("cannot represent denomination: ", err)
		return
	}

	chainId, err := strconv.Atoi(c.Args[3])
	if err != nil {
		c.Println("chainID could not be parse: ", err)
		return
	}

	c.Println("setting descriptor with values: ", uint16(keyIndex), currencyType, denomination)
	p := &model.Phonon{
		KeyIndex:     uint16(keyIndex),
		CurrencyType: currencyType,
		Denomination: denomination,
		ChainID: chainId,
	}

	// Capture Required Tag Fields
	requiredTags := model.CurrencyTypeTagsRequired[currencyType]
	newTags := make([]model.PhononTag, 0)
	if len(requiredTags) > 0 {
		c.Println("Additional tags are required.")

		for i, tag := range requiredTags {
			c.Printf("Input %v: ", tag)
			tagValue := c.ReadLine()

			if len(tagValue) == 0 {
				c.Println("Required tag cannot be null")
				return
			}
			newTags = append(newTags, model.PhononTag{TagName: requiredTags[i], TagValue: tagValue})
		}
	}

	if len(newTags) > 0 {
		p.AddTags(newTags)
	}

	err = activeCard.SetDescriptor(p)
	if err != nil {
		c.Println("could not set descriptor: ", err)
		return
	}
	c.Println("descriptor set successfully")
}

func redeemPhonon(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	numCorrectArgs := 1
	if len(c.Args) != numCorrectArgs {
		c.Println("incorrect number of args")
		return
	}

	keyIndex, err := strconv.ParseUint(c.Args[0], 10, 16)
	if err != nil {
		c.Println("could not parse keyIndex arg: ", err)
		return
	}
	selection := c.MultiChoice([]string{"no", "yes"},
		"Are you sure you wish to redeem this phonon?\n"+
			"Performing this action will permanently delete the phonon from the card and present you "+
			`with it's private key. After this, preserving this private key is your responsibility `+
			`and there will be no other way to retrieve it.`)
	if selection == 0 {
		c.Println("phonon redemption canceled")
		return
	}
	privKey, err := activeCard.DestroyPhonon(uint16(keyIndex))
	if err != nil {
		c.Printf("unable to redeem and destroy phonon at keyIndex %v, err: %v\n", keyIndex, err)
		return
	}
	c.Println("redeemed phonon at keyIndex: ", keyIndex)
	c.Println("private key: ")
	//TODO: Find a better encoding format
	c.Printf("%x\n", privKey.D)
}

func verifyBalance(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	numCorrectArgs := 1
	if len(c.Args) != numCorrectArgs {
		c.Println("incorrect number of args")
		return
	}

	keyIndex, err := strconv.ParseUint(c.Args[0], 10, 16)
	if err != nil {
		c.Println("could not parse keyIndex arg: ", err)
		return
	}
	privKey, err := activeCard.VerifyBalance(uint16(keyIndex))
	if err != nil {
		c.Printf("unable to verify contents of phonon %v, err: %v\n", keyIndex, err)
		return
	}
	c.Println("verified contents of phonon: ", privKey)
}
