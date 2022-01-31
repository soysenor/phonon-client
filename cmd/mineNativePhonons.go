/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"github.com/GridPlus/phonon-client/card"
	"github.com/spf13/cobra"
)

// mineNativePhononsCmd represents the mineNativePhonons command
var mineNativePhononsCmd = &cobra.Command{
	Use:   "mineNativePhonons [duration]",
	Short: "Begin mining native phonons",
	Long: `Begin mining native phonons.
	If called with no arguments command will repeatedly mine for phonons until cancelled.
	Pass a duration in go time syntax to mine for a specific duration instead.`,
	Run: func(cmd *cobra.Command, args []string) {
		mineNativePhonons()
	},
}

func init() {
	rootCmd.AddCommand(mineNativePhononsCmd)
}

func mineNativePhonons() {
	//Parse args

	//Loop that shit
	//Mine for a phonon
	cs, err := card.Connect(readerIndex)
	if err != nil {
		fmt.Println("could not connect to card. err: ", err)
		return
	}
	for {
		data, err := cs.MineNativePhonon()
		if err == card.ErrMiningFailed {
			fmt.Println("mining failed to find phonon. repeating attempt...")
		} else if err != nil {
			fmt.Println("error mining phonon. err: ", err)
			return
		} else {
			fmt.Printf("mined native phonon with raw data:\n%X", data)
		}
	}
}
