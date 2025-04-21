package cmd

import (
	"fmt"
	"net"
	"time"
	"bufio"
	"os"
	"strings"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var defensiveCmd = &cobra.Command{
	Use:   "defensive",
	Short: "Defensive Monitoring & Analysis",
}

var portmonCmd = &cobra.Command{
	Use:   "portmon [host] [interval]",
	Short: "Monitor open TCP ports in real time",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		interval, _ := time.ParseDuration(args[1])
		fmt.Println(color.HiCyanString("Monitoring open TCP ports on %s every %s... (Ctrl+C to stop)", host, interval))
		for {
			for port := 1; port <= 1024; port++ {
				address := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
				if err == nil {
					fmt.Printf("Port %d: %s\n", port, color.HiGreenString("OPEN"))
					conn.Close()
				}
			}
			time.Sleep(interval)
		}
	},
}

var logwatchCmd = &cobra.Command{
	Use:   "logwatch [file]",
	Short: "Tail a log file and highlight errors/failures",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Println(color.HiRedString("Log file error: %v", err))
			return
		}
		defer file.Close()
		fmt.Println(color.HiCyanString("Tailing log file: %s", args[0]))
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(strings.ToLower(line), "fail") || strings.Contains(strings.ToLower(line), "error") {
				fmt.Println(color.HiRedString(line))
			} else {
				fmt.Println(line)
			}
		}
	},
}

func init() {
	defensiveCmd.AddCommand(portmonCmd)
	defensiveCmd.AddCommand(logwatchCmd)
	rootCmd.AddCommand(defensiveCmd)
}
