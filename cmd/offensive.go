package cmd

import (
	"fmt"
	"os"
	"bufio"
	"net/http"
	"time"
	"strings"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var offensiveCmd = &cobra.Command{
	Use:   "offensive",
	Short: "Offensive Attacks & Exploitation",
}

var dirbruteCmd = &cobra.Command{
	Use:   "dirbrute [url] [wordlist]",
	Short: "Directory brute-force scanner",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		url, wordlist := args[0], args[1]
		file, err := os.Open(wordlist)
		if err != nil {
			fmt.Println(color.HiRedString("Wordlist error: %v", err))
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		client := &http.Client{Timeout: 2 * time.Second}
		for scanner.Scan() {
			path := scanner.Text()
			full := strings.TrimRight(url, "/") + "/" + path
			resp, err := client.Get(full)
			if err == nil && resp.StatusCode < 400 {
				fmt.Println(color.HiGreenString("Found: %s [%d]", full, resp.StatusCode))
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	},
}

func init() {
	offensiveCmd.AddCommand(dirbruteCmd)
	rootCmd.AddCommand(offensiveCmd)
}
