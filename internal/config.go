package internal

import (
	"encoding/json"
	"os"
	"io/ioutil"
	"github.com/fatih/color"
)

type FullConfig struct {
	DefaultOutputDir string            `json:"default_output_dir"`
	ScanTimeout      string            `json:"scan_timeout"`
	WordlistPath     string            `json:"wordlist_path"`
	APIKeys          map[string]string `json:"api_keys"`
	UserProfile      map[string]string `json:"user_profile"`
	CustomBanner     string            `json:"custom_banner"`
}

func LoadFullConfig() (*FullConfig, error) {
	file, err := os.Open("config.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var cfg FullConfig
	err = json.NewDecoder(file).Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveFullConfig(cfg *FullConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile("config.json", b, 0644)
}

func LoadConfig(store map[string]string) {
	file, err := os.Open("config.json")
	if err != nil {
		return // No config yet
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&store)
}

func SaveConfig(store map[string]string) {
	file, err := os.Create("config.json")
	if err != nil {
		println(color.HiRedString("[Config] Error saving config: %v", err))
		return
	}
	defer file.Close()
	json.NewEncoder(file).Encode(store)
}
