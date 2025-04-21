package cmd

import (
	"fmt"
	"os/exec"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Information Gathering & Reconnaissance",
}

var whoisCmd = &cobra.Command{
	Use:   "whois [domain]",
	Short: "Perform a whois lookup on a domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		fmt.Printf("[Recon] Whois lookup for: %s\n", domain)
		_, err := exec.LookPath("whois")
		if err != nil {
			fmt.Println(color.HiRedString("[Dependency] 'whois' command not found. Please install it for your OS."))
			return
		}
		out, err := exec.Command("whois", domain).CombinedOutput()
		if err != nil {
			fmt.Printf("Error running whois: %v\nOutput: %s\n", err, string(out))
			return
		}
		fmt.Println(string(out))
	},
}

func init() {
	reconCmd.AddCommand(whoisCmd)
	rootCmd.AddCommand(reconCmd)
}
