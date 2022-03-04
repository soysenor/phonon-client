package model

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestDenominationSetAndPrint(t *testing.T) {
	type denomTest struct {
		input  *big.Int
		output string
	}

	//36 zeros
	reallyBigString := "9000000000000000000000000000000000000"
	var reallyBigInt *big.Int
	reallyBigInt, _ = big.NewInt(0).SetString(reallyBigString, 10)

	tt := []denomTest{
		{big.NewInt(10), "10"},
		{big.NewInt(15), "15"},
		{big.NewInt(199), "199"},
		{big.NewInt(1000), "1000"},
		{big.NewInt(1500), "1500"},
		{big.NewInt(1200000000), "1200000000"},
		{big.NewInt(1000000000000000000), "1000000000000000000"},
		{reallyBigInt, reallyBigString},
	}
	log.SetLevel(log.DebugLevel)
	for _, test := range tt {
		d, err := NewDenomination(test.input)
		if err != nil {
			t.Error(err)
		}
		fmt.Printf("d: %+v\n", d)
		if d.String() != test.output {
			t.Error("error value output should be '100000' but was ", d.String())
		}
	}
}

func TestDenominationJSONUnmarshal(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	denomJSON := []byte(`{"Denomination":"1000"}`)

	type denominationStruct struct {
		Denomination Denomination
	}
	result := &denominationStruct{}
	correct := &Denomination{Base: 100, Exponent: 1}
	err := json.Unmarshal(denomJSON, result)
	if err != nil {
		t.Error("error unmarshaling denomination from JSON. err: ", err)
	}
	if result.Denomination.Base != 100 || result.Denomination.Exponent != 1 {
		t.Errorf("denomination did not unmarshal correctly. was %+v, should be %+v\n", result, correct)
	}
}

func TestDenominationJSONMarshal(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	type denominationStruct struct {
		Denomination Denomination
	}
	d, _ := NewDenomination(big.NewInt(1000))
	t.Log("printed d: ", d)
	input := denominationStruct{
		Denomination: d,
	}
	result, err := json.Marshal(&input)
	if err != nil {
		t.Error("error marshalling denomination: ", err)
	}
	t.Log("printed result: ", string(result))
	correct := []byte(`{"Denomination":"1000"}`)
	if string(result) != string(correct) {
		t.Errorf("resulting json incorrect. was %v, should be %v\n", string(result), string(correct))
	}
}
