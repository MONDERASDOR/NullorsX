package cmd

import (
	"fmt"
	"os/exec"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var postCmd = &cobra.Command{
	Use:   "post",
	Short: "Post-Exploitation Utilities",
}

var execCmd = &cobra.Command{
	Use:   "exec [command]",
	Short: "Execute a shell command and show output",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Println(color.HiRedString("Command error: %v\nOutput: %s", err, string(out)))
		}
		fmt.Println(string(out))
	},
}

func init() {
	postCmd.AddCommand(execCmd)
	rootCmd.AddCommand(postCmd)
}
