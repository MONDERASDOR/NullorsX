package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"nullorsx/internal"
	"github.com/fatih/color"
)

var reverseCmd = &cobra.Command{
	Use:   "reverse",
	Short: "Reverse Engineering & File Analysis",
}

var filetypeCmd = &cobra.Command{
	Use:   "filetype [file]",
	Short: "Identify file type by magic number",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ftype := internal.DetectFileType(args[0])
		fmt.Println(color.HiCyanString("File type: %s", ftype))
	},
}

func init() {
	reverseCmd.AddCommand(filetypeCmd)
	rootCmd.AddCommand(reverseCmd)
}
