package cmd

import (
	"fmt"
	"encoding/base64"
	"github.com/spf13/cobra"
	"nullorsx/internal"
)

var utilsCmd = &cobra.Command{
	Use:   "utils",
	Short: "Utilities: Encoder, Decoder, Hashing, Wordlists",
}

var hashCmd = &cobra.Command{
	Use:   "hash [type] [input]",
	Short: "Generate hash (md5, sha1, sha256) of input",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		typeStr, input := args[0], args[1]
		var hash string
		switch typeStr {
		case "md5":
			hash = internal.MD5Hash(input)
		case "sha1":
			hash = internal.SHA1Hash(input)
		case "sha256":
			hash = internal.SHA256Hash(input)
		default:
			hash = "Unknown hash type"
		}
		fmt.Printf("Hash: %s\n", hash)
	},
}

var encodeCmd = &cobra.Command{
	Use:   "encode [input]",
	Short: "Base64 encode a string",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		encoded := base64.StdEncoding.EncodeToString([]byte(args[0]))
		fmt.Printf("Base64: %s\n", encoded)
	},
}

var decodeCmd = &cobra.Command{
	Use:   "decode [base64]",
	Short: "Base64 decode a string",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		decoded, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			fmt.Printf("Decode error: %v\n", err)
			return
		}
		fmt.Printf("Decoded: %s\n", decoded)
	},
}

func init() {
	utilsCmd.AddCommand(hashCmd)
	utilsCmd.AddCommand(encodeCmd)
	utilsCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(utilsCmd)
}
