package top

import (
	"sync"

	// "os"
	"fmt"
	"net"

	"gary.core/config"
	"gary.core/modules"
	logger "go.uber.org/zap"
)

const (
	MODULE_NAME = "TOPPROXY"
)

// Listener ...
type Listener struct {
	Ch    chan error
	L     net.Listener
	Conns map[string]chan error
}

// Conn ...
type Conn struct {
	Conn net.Conn
	Ch   chan error
}

type Profile struct {
	ConfigPath     string
	InterfacePath  string
	JSONConfigAddr string
}

// TopProxy ...
type TopProxy struct {
	Listeners      map[int]*Listener
	mu             *sync.RWMutex
	LocalIP        string
	JSONConfigAddr string
}

// GetModulePtr ...
func GetModulePtr() *TopProxy {
	modulePtr := modules.GetModule(MODULE_NAME)
	if modulePtr == nil {
		return nil
	}

	return modulePtr.(*TopProxy)
}

func init() {
	fmt.Println("SequenceUuid::init()")
	modules.AddModule(&TopProxy{})
}

// InitModule ...
func (s *TopProxy) InitModule(cfg config.Configer, plugins ...modules.ServerPluginInterface) error {

	logger.Info("InitModuleApi(" + s.GetModuleName() + ")")

	moduleconfig := cfg.GetModuleConfig(s.GetModuleName())
	if moduleconfig != nil {
		privateprofile := &Profile{}
		err := moduleconfig.ParsePrivateConfig(privateprofile)
		if err == nil {
			config_path = privateprofile.ConfigPath
			interface_path = privateprofile.InterfacePath
			s.JSONConfigAddr = privateprofile.JSONConfigAddr
			s.LocalIP = cfg.(*config.Config).BindAddress
		} else {
			logger.Error(fmt.Errorf("InitModule(%s), parse private module config failed:%v", s.GetModuleName(), moduleconfig.PrivateConfig))
		}
	} else {
		logger.Error(fmt.Errorf("InitModule(%s), can't find module config", s.GetModuleName()))
	}

	s.Listeners = map[int]*Listener{}
	s.mu = new(sync.RWMutex)

	go s.register()
	return nil
}

// GetModuleName ...
func (s *TopProxy) GetModuleName() string {
	return MODULE_NAME
}

// ReleaseModule ...
func (s *TopProxy) ReleaseModule() {

	logger.Info("ReleaseModuleApi(" + s.GetModuleName() + ")")
}

// TestModule ...
func (s *TopProxy) TestModule(cfg config.Configer) {
	logger.Info("TestModuleApi(" + s.GetModuleName() + ")")
}
