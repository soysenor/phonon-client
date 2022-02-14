package config

import (
	"github.com/GridPlus/phonon-client/cert"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	//Global
	LogLevel log.Level //A logrus logLevel
	//PhononCommandSet
	AppletCACert []byte //One of the CA certificates listed in the cert package

	//EthChainService
	EthChainServiceApiKey string
}

type PhononCommandSetConfig struct {
}

type EthChainServiceConfig struct {
	ApiKey string
}

func DefaultConfig() Config {
	//Add viper/commandline integration later
	conf := Config{
		AppletCACert:          cert.PhononDemoCAPubKey,
		LogLevel:              log.DebugLevel,
		EthChainServiceApiKey: "",
	}
	return conf
}

func SetDefaultConfig() {
	viper.SetDefault("AppletCACert", cert.PhononDemoCAPubKey)
	viper.SetDefault("LogLevel", log.DebugLevel)
}

func LoadConfig() (config Config, err error) {
	SetDefaultConfig()
	viper.AddConfigPath("$HOME/.phonon/")
	viper.SetConfigName("phonon")
	viper.SetConfigType("yml")

	viper.SetEnvPrefix("phonon")
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		log.Debug("config file not found, using default config")
	}
	if err != nil {
		log.Error("unable to set configuration. err: ", err)
		return DefaultConfig(), err
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return DefaultConfig(), err
	}
	return config, nil
}
