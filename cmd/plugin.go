package cmd

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Plugin Management",
}

var pluginListCmd = &cobra.Command{
	Use:   "list [directory]",
	Short: "List available plugins in a directory",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		files, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("Error reading directory: %v\n", err)
			return
		}
		fmt.Println("Available plugins:")
		for _, f := range files {
			if !f.IsDir() {
				fmt.Println("-", f.Name())
			}
		}
	},
}

func init() {
	pluginCmd.AddCommand(pluginListCmd)
	rootCmd.AddCommand(pluginCmd)
}
