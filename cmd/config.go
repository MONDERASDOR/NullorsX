package cmd

import (
	"fmt"
	"nullorsx/internal"
	"github.com/spf13/cobra"
)

var configStore = make(map[string]string)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration (API keys, output, etc.)",
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key, value := args[0], args[1]
		configStore[key] = value
		internal.SaveConfig(configStore)
		fmt.Printf("Config %s set to %s\n", key, value)
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		if val, ok := configStore[key]; ok {
			fmt.Printf("%s: %s\n", key, val)
		} else {
			fmt.Printf("Config %s not set\n", key)
		}
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	rootCmd.AddCommand(configCmd)
}
