package utils

import (
	"log"

	"github.com/spf13/viper"
)

func ParseConfigs() func() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	viper.SetEnvPrefix("PGO")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("Config file not found. Will create one based on defaults")
			viper.SafeWriteConfig()
			ParseConfigs()
		} else {
			log.Fatal(err)
		}
	}
	return func() {
		viper.WriteConfig()
	}
}
