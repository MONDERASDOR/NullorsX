package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Web Attacks & Scanning",
}

var headersCmd = &cobra.Command{
	Use:   "headers [url]",
	Short: "Fetch HTTP headers for a URL",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := http.Head(args[0])
		if err != nil {
			fmt.Println(color.HiRedString("HTTP error: %v", err))
			return
		}
		defer resp.Body.Close()
		fmt.Println(color.HiCyanString("Headers for %s:", args[0]))
		for k, v := range resp.Header {
			fmt.Printf("%s: %s\n", color.HiYellowString(k), strings.Join(v, ", "))
		}
	},
}

func init() {
	webCmd.AddCommand(headersCmd)
	rootCmd.AddCommand(webCmd)
}
