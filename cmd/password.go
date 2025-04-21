package cmd

import (
	"bufio"
	"fmt"
	"os"
	"github.com/spf13/cobra"
	"nullorsx/internal"
)

var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Password Attacks & Cracking",
}

var crackCmd = &cobra.Command{
	Use:   "crack [hash] [wordlist]",
	Short: "Crack a hash using a wordlist",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		hash, wordlist := args[0], args[1]
		file, err := os.Open(wordlist)
		if err != nil {
			fmt.Printf("Wordlist error: %v\n", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := scanner.Text()
			if internal.MD5Hash(word) == hash || internal.SHA1Hash(word) == hash || internal.SHA256Hash(word) == hash {
				fmt.Printf("Found: %s\n", word)
				return
			}
		}
		fmt.Println("Not found in wordlist.")
	},
}

func init() {
	passwordCmd.AddCommand(crackCmd)
	rootCmd.AddCommand(passwordCmd)
}
