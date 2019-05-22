package top

import (
	. "ksat.model/utils"
)

// ChangeIP 改变ip参数
type ChangeIP struct {
	Name     string
	IsStatic bool
	IP       string
	Mask     string
	GateWay  string
}

// Proxy ...
type Proxy struct {
	LocalPort  int      `json:"LocalPort"`
	RemotePort int      `json:"RemotePort"`
	RemoteIP   string   `json:"RemoteIP"`
	IsActive   bool     `json:"IsActive"`
	Conns      []string `json:"Conns"`
}

// SlaveProxy ...
type SlaveProxy struct{}

// GetInterfaceArgs ...
type GetInterfaceArgs struct {
	Oauth string `json:"Oauth"`
}

// AddProxyArgs ...
type AddProxyArgs struct {
	LocalPort  int32  `json:"LocalPort"`
	RemotePort int32  `json:"RemotePort"`
	RemoteIP   string `json:"RemoteIP"`
	Oauth      string `json:"Oauth"`
}

// DelProxyArgs ...
type DelProxyArgs struct {
	LocalPort int32  `json:"LocalPort"`
	Oauth     string `json:"Oauth"`
}

// ModProxyArgs ...
type ModProxyArgs struct {
	OldPort    int32  `json:"OldPort"`
	LocalPort  int32  `json:"LocalPort"`
	RemotePort int32  `json:"RemotePort"`
	RemoteIP   string `json:"RemoteIP"`
	Oauth      string `json:"Oauth"`
}

// ListProxyArgs ...
type ListProxyArgs struct {
	LocalPort  int32  `json:"LocalPort"`
	RemotePort int32  `json:"RemotePort"`
	RemoteIP   string `json:"RemoteIP"`
	Oauth      string `json:"Oauth"`
}

// AuthProxyArgs ...
type AuthProxyArgs struct {
	LocalPort int32  `json:"LocalPort"`
	Auth      int32  `json:"Auth"` // 1 无权限， 2 有权限
	UserID    int32  `json:"UserID"`
	Oauth     string `json:"Oauth"`
}

// DelAuthArgs ...
type DelAuthArgs struct {
	LocalPort int32  `json:"LocalPort"`
	UserID    int32  `json:"UserID"`
	Oauth     string `json:"Oauth"`
}

type ListAuthArgs struct {
	LocalPort int32  `json:"LocalPort"`
	Oauth     string `json:"Oauth"`
}

// ModAuthArgs ...
type ModAuthArgs struct {
	LocalPort int32  `json:"LocalPort"`
	Auth      int32  `json:"Auth"` // 1 无权限， 2 有权限
	UserID    int32  `json:"UserID"`
	Oauth     string `json:"Oauth"`
}

// StartProxyArgs ...
type StartProxyArgs struct {
	LocalPort int32  `json:"LocalPort"`
	Oauth     string `json:"Oauth"`
}

// StopProxyArgs ...
type StopProxyArgs struct {
	Oauth     string `json:"Oauth"`
	LocalPort int32  `json:"LocalPort"`
}

// StopConnArgs ...
type StopConnArgs struct {
	Oauth      string `json:"Oauth"`
	LocalPort  int32  `json:"LocalPort"`
	RemoteAddr string `json:"RemoteAddr"`
}

// InterfaceArgs ...
type InterfaceArgs struct {
	Oauth     string     `json:"Oauth"`
	Interface []ChangeIP `json:"Interface"`
}

// GetGeneralInfoArgs ...
type GetGeneralInfoArgs struct {
	Oauth string `json:"Oauth"`
}

// SetGeneralInfoArgs ...
type SetGeneralInfoArgs struct {
	Oauth     string `json:"Oauth"`
	Master    string `json:"Master"`
	Heartbeat string `json:"Heartbeat"`
	Name      string `json:"Name"`
}

// ListAuthItem ...
type ListAuthItem struct {
	User *User  `json:"User"`
	Auth string `json:"Auth"`
}

// GeneralInfo ...
type GeneralInfo struct {
	Master    string `json:"Master"`
	Heartbeat string `json:"Heartbeat"`
	Name      string `json:"Name"`
}

// // RegisterInfo ...
// type RegisterInfo struct {
// 	Version string `json:"Version"`
// 	Name    string `json:"Name"`
// 	Proxys  []byte `json:"Proxys"`
// }
