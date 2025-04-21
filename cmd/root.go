package cmd

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
	"nullorsx/internal"
)

var rootCmd = &cobra.Command{
	Use:   "nullorsX",
	Short: "nullorsX - The Ultimate Pentesting & Cybersecurity Toolkit",
	Long: `nullorsX - The Ultimate Pentesting & Cybersecurity Toolkit

For Red Teamers, Blue Teamers, and Security Enthusiasts. Ethical use only!
By using this tool, you agree to use it for authorized testing only.
Created by MONDERASDOR`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := internal.LoadFullConfig()
		if err == nil && cfg.CustomBanner != "" {
			fmt.Println(color.HiMagentaString(cfg.CustomBanner))
		} else {
			printBanner()
		}
		fmt.Println(color.HiYellowString("Welcome to nullorsX! Use --help to see available modules."))
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(color.HiRedString("Error: %v", err))
		os.Exit(1)
	}
}

func printBanner() {
	banner := `

  _   _       _ _                 _____  
 | \ | |     | | |               / ____| 
 |  \| | ___ | | | ___ _ __ ___ | (___   
 | . ` + "|" + `/ _ \| | |/ _ \ '_ \\ _ \\ \___ \  
 | |\  | (_) | | |  __/ | | | | |____) | 
 |_| \_|\___/|_|_|\___|_| |_| |_|_____/  

 The Ultimate Pentesting & Cybersecurity Toolkit
 For Red Teamers, Blue Teamers, and Security Enthusiasts.
 Ethical use only!
 By using this tool, you agree to use it for authorized testing only.
 Created by MONDERASDOR

`
	fmt.Println(color.HiMagentaString(banner))
}
