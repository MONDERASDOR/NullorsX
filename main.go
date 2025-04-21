package main

import (
	"nullorsx/cmd"
	"nullorsx/internal"
)

var configStore = make(map[string]string)

func main() {
	internal.LoadConfig(configStore)
	cmd.Execute()
}
