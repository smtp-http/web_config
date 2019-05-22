package top

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	. "gary.core/common"
	"go.uber.org/zap"
	logger "go.uber.org/zap"
	"ksat.model/utils"
)

// JSONConfig ...配置命令
type JSONConfig struct {
	Port  uint16 `json:"port,omitempty"`
	Speed uint32 `json:"speed,omitempty"`
	IP    string `json:"ip,omitempty"`
	To    uint16 `json:"to,omitempty"`
}

// TransData ...
type TransData struct {
	Name   string     `json:"Name"`
	Config JSONConfig `json:"Config"`
}

// LoadJSONConfig ...读
func (m *TopProxy) LoadJSONConfig(oauth string) (interface{}, int) {

	if len(m.JSONConfigAddr) <= 0 {
		return fmt.Sprintf("在文件不存在"), ERR_NOT_EXISTING
	}

	br, err := ioutil.ReadFile(m.JSONConfigAddr)
	if err != nil {
		zap.Errorf("read json config file failed: %v", err.Error())
		// fmt.Println(err.Error())
		return fmt.Sprintf("读取配置文件时出错"), ERR_READ_FILE
	}
	mconfig := map[string]JSONConfig{}
	err = json.Unmarshal(br, &mconfig)
	if err != nil {
		zap.Errorf("unmarshal json config failed: %v", err.Error())
		// fmt.Println(err.Error())
		return fmt.Sprintf("解析配置文件时出错"), ERR_PARSE_CONFIG
	}

	resp := make([]*TransData, 0)
	for k, v := range mconfig {
		resp = append(resp, &TransData{
			Name:   k,
			Config: v,
		})
	}

	return resp, ERR_SUCCESS
}

// SaveJSONConfigArgs ...
type SaveJSONConfigArgs struct {
	Oauth  string      `json:"Oauth"`
	Config []TransData `json:"Config"`
}

// SaveJSONConfig ...写
func (m *TopProxy) SaveJSONConfig(args SaveJSONConfigArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("SaveJSONConfig failed, no auth")
		return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
	}
	if len(m.JSONConfigAddr) <= 0 {
		return fmt.Sprintf("无法找到配置文件路径"), ERR_NOT_EXISTING
	}

	mconfig := map[string]JSONConfig{}
	for _, item := range args.Config {
		if len(item.Config.IP) > 0 {
			if !isValidIP(item.Config.IP) {
				return fmt.Sprintf("%v invalid ip %v", item.Name, item.Config.IP), ERR_INVALID_PARAM
			}
		}
		mconfig[item.Name] = item.Config
	}
	br, err := json.Marshal(mconfig)
	if err != nil {
		zap.Errorf("marshal json config failed: %v", err.Error())
		return fmt.Sprintf("解析配置文件时出错"), ERR_PARSE_CONFIG
	}

	err = ioutil.WriteFile(m.JSONConfigAddr, br, 666)
	if err != nil {
		zap.Errorf("write to config file failed: %v", err.Error())
		return fmt.Sprintf("写入配置文件时出错"), ERR_SAVE_FILE
	}
	return args.Config, ERR_SUCCESS
}
