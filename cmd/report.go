package cmd

import (
	"fmt"
	"io/ioutil"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Reporting & Output",
}

var saveCmd = &cobra.Command{
	Use:   "save [file] [content]",
	Short: "Save content to a file",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		err := ioutil.WriteFile(args[0], []byte(args[1]), 0644)
		if err != nil {
			fmt.Println(color.HiRedString("Save error: %v", err))
			return
		}
		fmt.Println(color.HiGreenString("Saved to %s", args[0]))
	},
}

func init() {
	reportCmd.AddCommand(saveCmd)
	rootCmd.AddCommand(reportCmd)
}
