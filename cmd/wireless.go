package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var wirelessCmd = &cobra.Command{
	Use:   "wireless",
	Short: "Wireless & Bluetooth Tools",
}

var wifiListCmd = &cobra.Command{
	Use:   "wifi-list",
	Short: "List available WiFi networks",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS == "windows" {
			_, err := exec.LookPath("netsh")
			if err != nil {
				fmt.Println(color.HiRedString("[Dependency] 'netsh' command not found. This command is required on Windows for WiFi scanning."))
				return
			}
			cmd := exec.Command("netsh", "wlan", "show", "networks")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(color.HiRedString("WiFi scan error: %v\nOutput: %s", err, string(out)))
				return
			}
			fmt.Println(color.HiCyanString("Available WiFi networks:"))
			fmt.Println(string(out))
		} else {
			_, err := exec.LookPath("nmcli")
			if err != nil {
				fmt.Println(color.HiRedString("[Dependency] 'nmcli' command not found. This command is required on Linux for WiFi scanning."))
				return
			}
			cmd := exec.Command("nmcli", "dev", "wifi")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(color.HiRedString("WiFi scan error: %v\nOutput: %s", err, string(out)))
				return
			}
			fmt.Println(color.HiCyanString("Available WiFi networks:"))
			fmt.Println(string(out))
		}
	},
}

func init() {
	wirelessCmd.AddCommand(wifiListCmd)
	rootCmd.AddCommand(wirelessCmd)
}
