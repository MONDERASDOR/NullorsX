package cmd

import (
	"fmt"
	"net"
	"time"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scanning & Enumeration",
}

var portscanCmd = &cobra.Command{
	Use:   "portscan [host] [startPort] [endPort]",
	Short: "Scan TCP ports on a host",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		start, end := args[1], args[2]
		startPort, endPort := 0, 0
		fmt.Sscanf(start, "%d", &startPort)
		fmt.Sscanf(end, "%d", &endPort)
		fmt.Printf("[Scan] Scanning %s ports %d-%d...\n", host, startPort, endPort)
		for port := startPort; port <= endPort; port++ {
			address := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
			if err == nil {
				fmt.Printf("Port %d: OPEN\n", port)
				conn.Close()
			}
		}
	},
}

func init() {
	scanCmd.AddCommand(portscanCmd)
	rootCmd.AddCommand(scanCmd)
}
