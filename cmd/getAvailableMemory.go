/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

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

	"github.com/GridPlus/phonon-client/orchestrator"
	"github.com/spf13/cobra"
)

// getAvailableMemoryCmd represents the getAvailableMemory command
var getAvailableMemoryCmd = &cobra.Command{
	Use:   "getAvailableMemory",
	Short: "Retrieve the card's available memory statistics",
	Long: `Retrieve the card's available memory statistics.
	Returns persistent memory, transient memory on reset, then transient memory on deselect`,
	Run: func(cmd *cobra.Command, args []string) {
		cs, err := orchestrator.QuickSecureConnection(readerIndex)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = cs.VerifyPIN("111111")
		if err != nil {
			fmt.Println(err)
			return
		}
		// cs, err := card.Connect()
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }

		persistentMem, onResetMem, onDeselectMem, err := cs.GetAvailableMemory()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("persistent memory: ", persistentMem)
		fmt.Println("transient on reset memory: ", onResetMem)
		fmt.Println("transient on deselect memory: ", onDeselectMem)
	},
}

func init() {
	rootCmd.AddCommand(getAvailableMemoryCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getAvailableMemoryCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getAvailableMemoryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
