package top

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ksat.model/utils"

	"ksat.model/tcpproxy/top/conf"

	logger "go.uber.org/zap"
	arm "ksat.model/pms/terminal"

	. "gary.core/common"
)

var (
	cfgMnager      = conf.GetSvnConfigManagerInstance()
	ipRegexp       = "(2(5[0-5]{1}|[0-4]\\d{1})|[0-1]?\\d{1,2})(\\.(2(5[0-5]{1}|[0-4]\\d{1})|[0-1]?\\d{1,2})){3}"
	config_path    string
	interface_path string
)

// Test ...
func (m *TopProxy) Test() (interface{}, int) {
	return rand.Int(), ERR_SUCCESS
}

// GetInterface ...
func (m *TopProxy) GetInterface(args GetInterfaceArgs) (interface{}, int) {
	type GetInterfaceResp struct {
		Inf  []ChangeIP `json:"Inf"`
		OS   string     `json:"OS"`
		ARCH string     `json:"ARCH"`
	}
	inf, err := getInterface()
	if err != nil {
		logger.Infof("get interface failed: %v", err.Error())
		return err.Error(), ERR_FAILED
	}

	return GetInterfaceResp{
		Inf:  inf,
		OS:   runtime.GOOS,
		ARCH: runtime.GOARCH,
	}, ERR_SUCCESS
}

// AddProxy ...
func (m *TopProxy) AddProxy(args AddProxyArgs) (interface{}, int) {
	if !isValidIP(args.RemoteIP) {
		logger.Infof("add proxy to invalid ip %v", args.RemoteIP)
		return fmt.Sprintf("invalid ip %v", args.RemoteIP), ERR_INVALID_PARAM
	}
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("add proxy %v to %v:%v failed, no auth", args.LocalPort, args.RemoteIP, args.RemotePort)
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	err, proxys := cfgMnager.ReadConfigFileSection(config_path, "proxy")
	if err != nil {
		logger.Infof("AddProxy check if proxy exists from config file failed: %v", err.Error())
		return err.Error(), ERR_DISABLED
	}
	strport := strconv.Itoa(int(args.LocalPort))
	remote := fmt.Sprintf("%v:%v", args.RemoteIP, args.RemotePort)
	for k, v := range proxys {
		if strport == k {
			logger.Infof("AddProxy local port %v already in use", strport)
			return fmt.Sprintf("local port %v already in use", strport), ERR_DISABLED
		}
		if v == remote {
			logger.Infof("AddProxy proxy to %v already exists at port %v", remote, k)
			return fmt.Sprintf("proxy to %v already exists at port %v", remote, k), ERR_EXISTING
		}
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%v", args.LocalPort))
	if err != nil {
		logger.Infof("AddProxy from :%v to %v:%v failed: %v", args.LocalPort, args.RemoteIP, args.RemotePort, err.Error())
		return err.Error(), ERR_DISABLED
	}
	l.Close()

	err = cfgMnager.ModifyConfigFile(config_path, "proxy", map[string]string{
		strconv.Itoa(int(args.LocalPort)): fmt.Sprintf("%v:%v", args.RemoteIP, args.RemotePort),
	})

	if err != nil {
		logger.Infof("save proxy(%v) info failed: %v", args.LocalPort, err.Error())
		return fmt.Sprintf("Save to config file failed: %v", err.Error()), ERR_SAVE_FILE
	}

	return nil, ERR_SUCCESS
}

// DelProxy ...
func (m *TopProxy) DelProxy(args DelProxyArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}

	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("delete proxy on port %v failed, no auth", args.LocalPort)
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	m.mu.Lock()
	if l, ok := m.Listeners[int(args.LocalPort)]; ok {
		l.Ch <- errors.New("close")
	}
	m.mu.Unlock()

	err = cfgMnager.DeleteSection(config_path, strconv.Itoa(int(args.LocalPort))) //删除授权信息
	if err != nil {
		logger.Infof("delete proxy(%v) auth info from config file failed: %v", args.LocalPort, err.Error())
		return fmt.Sprintf("delete proxy auth info from config file failed: %v", err.Error()), ERR_SAVE_FILE
	}
	err = cfgMnager.DeleteKey(config_path, "proxy", strconv.Itoa(int(args.LocalPort))) //删除代理信息
	if err != nil {
		logger.Infof("delete proxy(%v) info from config file failed: %v", args.LocalPort, err.Error())
		return fmt.Sprintf("delete proxy info from config file failed: %v", err.Error()), ERR_SAVE_FILE
	}

	return nil, ERR_SUCCESS
}

// ModProxy ...
func (m *TopProxy) ModProxy(args ModProxyArgs) (interface{}, int) {
	r, code := m.StopProxy(StopProxyArgs{
		Oauth:     args.Oauth,
		LocalPort: args.OldPort,
	})
	if code != ERR_SUCCESS {
		return r, code
	}
	r, code = m.DelProxy(DelProxyArgs{
		Oauth:     args.Oauth,
		LocalPort: args.OldPort,
	})
	if code != ERR_SUCCESS {
		return r, code
	}
	return m.AddProxy(AddProxyArgs{
		Oauth:      args.Oauth,
		LocalPort:  args.LocalPort,
		RemoteIP:   args.RemoteIP,
		RemotePort: args.RemotePort,
	})
}

// ListProxy ...
func (m *TopProxy) ListProxy(args ListProxyArgs) (interface{}, int) {
	err, mp := cfgMnager.ReadConfigFileSection(config_path, "proxy")
	if err != nil {
		logger.Infof("get proxys failed: %v", err.Error())
		return err.Error(), ERR_READ_FILE
	}
	proxys := map[string]string{}
	copymap(mp, &proxys)
	resp := make([]*Proxy, 0)
	strport := strconv.Itoa(int(args.LocalPort))
	strrport := strconv.Itoa(int(args.RemotePort))
	for k, v := range proxys {
		if strings.Index(v, ":") < 0 {
			delete(proxys, k)
			continue
		}
		if args.LocalPort > 0 && k != strport {
			delete(proxys, k)
			continue
		}
		if len(args.RemoteIP) > 0 && strings.Split(v, ":")[0] != args.RemoteIP {
			delete(proxys, k)
			continue
		}
		if args.RemotePort > 0 && strings.Split(v, ":")[1] != strrport {
			delete(proxys, k)
			continue
		}
	}

	for k, v := range proxys {
		if strings.Index(v, ":") < 0 {
			continue
		}
		lp, _ := strconv.Atoi(k)
		rp, _ := strconv.Atoi(strings.Split(v, ":")[1])
		proxy := &Proxy{
			LocalPort:  lp,
			RemoteIP:   strings.Split(v, ":")[0],
			RemotePort: rp,
			Conns:      []string{},
		}
		m.mu.RLock()
		ls, ok := m.Listeners[lp]
		proxy.IsActive = ok
		if ok {
			for addr := range ls.Conns {
				proxy.Conns = append(proxy.Conns, addr)
			}
		}
		m.mu.RUnlock()

		resp = append(resp, proxy)
	}

	return resp, ERR_SUCCESS
}

// AuthProxy ...
func (m *TopProxy) AuthProxy(args AuthProxyArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("AuthProxy on port %v failed, no auth", args.LocalPort)
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	err = cfgMnager.ModifyConfigFile(config_path, strconv.Itoa(int(args.LocalPort)), map[string]string{
		strconv.Itoa(int(args.UserID)): strconv.Itoa(int(args.Auth)),
	})
	if err != nil {
		logger.Infof("add proxy(%v) auth info from config file failed: %v", args.LocalPort, err.Error())
		return fmt.Sprintf("add proxy auth info from config file failed: %v", err.Error()), ERR_SAVE_FILE
	}

	return nil, ERR_SUCCESS
}

// DelAuth ...
func (m *TopProxy) DelAuth(args DelAuthArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("delete proxy auth on port %v failed, no auth", args.LocalPort)
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	err = cfgMnager.DeleteKey(config_path, strconv.Itoa(int(args.LocalPort)), strconv.Itoa(int(args.UserID)))
	if err != nil {
		logger.Infof("delete proxy(%v) auth info from config file failed: %v", args.LocalPort, err.Error())
		return fmt.Sprintf("delete proxy auth info from config file failed: %v", err.Error()), ERR_SAVE_FILE
	}

	return nil, ERR_SUCCESS
}

// ListAuth ...
func (m *TopProxy) ListAuth(args ListAuthArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("ListAuth on port %v failed, no auth", args.LocalPort)
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	resp := make([]*ListAuthItem, 0)
	err, authz := cfgMnager.ReadConfigFileSection(config_path, strconv.Itoa(int(args.LocalPort)))
	if err != nil {
		logger.Infof("ListAuth find info in config file failed: %v", err.Error())
		return resp, ERR_SUCCESS
	}

	for k, v := range authz {
		user, err := utils.GetUserByID(args.Oauth, k, "11")
		if err != nil {
			logger.Infof("cannot find user by id %v", err.Error())
			continue
		}
		resp = append(resp, &ListAuthItem{
			Auth: v,
			User: user,
		})
	}

	return resp, ERR_SUCCESS
}

// ModAuth ...
func (m *TopProxy) ModAuth(args ModAuthArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("Modify auth on port %v failed, no auth", args.LocalPort)
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	err = cfgMnager.ModifyConfigFile(config_path, strconv.Itoa(int(args.LocalPort)), map[string]string{
		strconv.Itoa(int(args.UserID)): strconv.Itoa(int(args.Auth)),
	})
	if err != nil {
		logger.Infof("modify proxy(%v) auth info from config file failed: %v", args.LocalPort, err.Error())
		return fmt.Sprintf("modify proxy auth info from config file failed: %v", err.Error()), ERR_SAVE_FILE
	}

	return nil, ERR_SUCCESS
}

// SlaveProxy ...
func (m *TopProxy) SlaveProxy(args SlaveProxy) (interface{}, int) {
	return "not support yet", ERR_FAILED
}

// StartProxy ...
func (m *TopProxy) StartProxy(args StartProxyArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}

	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		err, value := cfgMnager.ReadConfigFile(config_path, strconv.Itoa(int(args.LocalPort)), ui.EmpCode)
		if err != nil {
			logger.Infof("start proxy(at %v) failed: %v", args.LocalPort, err.Error())
			return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
		}
		if value <= "1" {
			return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
		}
	}

	err, remote := cfgMnager.ReadConfigFile(config_path, "proxy", strconv.Itoa(int(args.LocalPort)))
	if err != nil {
		logger.Infof("cannot find proxy at port %v", args.LocalPort)
		return fmt.Sprintf("cannot find proxy at port %v", args.LocalPort), ERR_FAILED
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%v", args.LocalPort))
	if err != nil {
		logger.Errorf("listen tcp on %v failed: %v", args.LocalPort, err.Error())
		return err.Error(), ERR_FAILED
	}

	go func() {
		ch := make(chan error)
		ls := &Listener{
			Ch:    ch,
			L:     l,
			Conns: map[string]chan error{},
		}
		m.mu.Lock()
		m.Listeners[int(args.LocalPort)] = ls
		m.mu.Unlock()

		stopCh := make(chan int)

		go func() {
			for {
				conn, err := l.Accept()
				if err != nil && ls.Ch != nil {
					ls.Ch <- err
					return
				}
				closeCh := make(chan error)

				logger.Infof("%v connect at %v proxy to %v", conn.RemoteAddr(), args.LocalPort, remote)

				m.mu.Lock()
				m.Listeners[int(args.LocalPort)].Conns[conn.RemoteAddr().String()] = closeCh
				m.mu.Unlock()

				go m.handleTCP(conn, remote, stopCh, closeCh, int(args.LocalPort))
			}
		}()

		err := <-ls.Ch

		close(stopCh) //关闭现有链接
		l.Close()     //停止监听

		m.mu.Lock()
		delete(m.Listeners, int(args.LocalPort))
		m.mu.Unlock()

		logger.Infof("quit proxy(%v): %v", args.LocalPort, err.Error())
	}()

	return nil, ERR_SUCCESS
}

// StopProxy ...
func (m *TopProxy) StopProxy(args StopProxyArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		err, value := cfgMnager.ReadConfigFile(config_path, strconv.Itoa(int(args.LocalPort)), ui.EmpCode)
		if err != nil {
			logger.Infof("stop proxy(at %v) failed: %v", args.LocalPort, err.Error())
			return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
		}
		if value <= "1" {
			return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
		}
	}

	m.mu.Lock()
	if l, ok := m.Listeners[int(args.LocalPort)]; ok {
		l.Ch <- fmt.Errorf("%v request to close", ui.EmpName)
	}
	m.mu.Unlock()

	return nil, ERR_SUCCESS
}

// StopConn ...
func (m *TopProxy) StopConn(args StopConnArgs) (interface{}, int) {
	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}
	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		err, value := cfgMnager.ReadConfigFile(config_path, strconv.Itoa(int(args.LocalPort)), ui.EmpCode)
		if err != nil {
			logger.Infof("stop proxy(at %v) failed: %v", args.LocalPort, err.Error())
			return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
		}
		if value <= "1" {
			return fmt.Sprintf("no auth"), ERR_NOT_PERMISSION
		}
	}

	m.mu.Lock()
	if l, ok := m.Listeners[int(args.LocalPort)]; ok {
		for addr, ch := range l.Conns {
			if addr == args.RemoteAddr {
				ch <- fmt.Errorf("%v request to close this conn", ui.EmpName)
				break
			}
		}
	}
	m.mu.Unlock()

	return nil, ERR_SUCCESS
}

// SetInterface ...
func (m *TopProxy) SetInterface(args InterfaceArgs) (interface{}, int) {
	if runtime.GOARCH != "arm" || runtime.GOOS != "linux" {
		return fmt.Sprintf("当前系统不支持此功能"), ERR_FAILED
	}
	for _, item := range args.Interface {
		if item.IsStatic && (!isValidIP(item.IP) || !isValidIP(item.GateWay) || (!isValidIP(item.Mask) && len(item.Mask) != 8)) {
			logger.Infof("change interface %v config to invalid static ip %v or gateway %v or netmask %v", item.Name, item.IP, item.GateWay, item.Mask)
			return fmt.Sprintf("%v invalid ip %v or invalid gateway %v or invalid mask %v", item.Name, item.IP, item.GateWay, item.Mask), ERR_INVALID_PARAM
		}
	}
	logger.Infof("SetInterface: args: %+v", args)

	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}

	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("SetInterface failed, no auth")
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	go func() {
		err := changeIP(args.Interface) // 修改ip并重启电脑
		if err != nil {
			logger.Infof("err: %v", err.Error())
		}
	}()

	return nil, ERR_SUCCESS
}

// GetGeneralInfo ...
func (m *TopProxy) GetGeneralInfo(args GetGeneralInfoArgs) (interface{}, int) {
	logger.Infof("GetGeneralInfo: args: %+v", args)

	_, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}

	info := GeneralInfo{}
	err, gen := cfgMnager.ReadConfigFileSection(config_path, "general")
	if err == nil {
		master, ok := gen["master"]
		if !ok {
			logger.Infof("get master failed")
		}
		heartbeat, ok := gen["heartbeat"]
		if !ok {
			logger.Infof("get heartbeat failed")
		}
		name, ok := gen["name"]
		if !ok {
			logger.Infof("get name failed")
		}
		info.Name = name
		info.Master = master
		info.Heartbeat = heartbeat
	} else {
		logger.Infof("read general section failed: %v", err.Error())
	}

	return info, ERR_SUCCESS
}

// SetGeneralInfo ...
func (m *TopProxy) SetGeneralInfo(args SetGeneralInfoArgs) (interface{}, int) {
	logger.Infof("SetGeneralInfo: args: %+v", args)

	ui, _, err := utils.GetUserByToken(args.Oauth)
	if err != nil {
		logger.Infof("get user by token(%v) failed: %v", args.Oauth, err.Error())
		return fmt.Sprintf("get user by token(%v) failed: %v", args.Oauth, err.Error()), ERR_TOKEN_EXPIRED
	}

	if !utils.CheckAuth(args.Oauth, "11", "133", ui.EmpCode) {
		logger.Infof("SetInterface failed, no auth")
		return fmt.Errorf("no auth"), ERR_NOT_PERMISSION
	}

	if _, err = strconv.Atoi(args.Heartbeat); err != nil {
		return fmt.Errorf("invalid Heartbeat value: %v, must be a integer", args.Heartbeat), ERR_INVALID_PARAM
	}

	err = cfgMnager.ModifyConfigFile(config_path, "general", map[string]string{
		"name":      args.Name,
		"heartbeat": args.Heartbeat,
		"master":    args.Master,
	})

	if err != nil {
		logger.Errorf("save general info failed: %v", err.Error())
		return fmt.Sprintf("save to config file failed: %v", err.Error()), ERR_SAVE_FILE
	}

	return nil, ERR_SUCCESS
}

func (m *TopProxy) handleTCP(conn net.Conn, proxy string, stopCh chan int, closeCh chan error, port int) {
	defer conn.Close()
	remoteaddr := conn.RemoteAddr().String()

	if len(proxy) <= 0 || strings.Index(proxy, ":") < 0 {
		return
	}
	dtcp, err := net.Dial("tcp", proxy)
	if err != nil {
		logger.Errorf("conn to  %v failed：%v", proxy, err.Error())
		return
	}
	defer dtcp.Close()

	c := make(chan error, 1)
	go func(err chan<- error, stcp, dtcp net.Conn) {
		for {
			_, err := io.Copy(stcp, dtcp)
			// if err == nil {
			// 	logger.Infof("send %v bytes from %v to %v", n, dtcp.RemoteAddr().String(), stcp.RemoteAddr().String())
			// }
			c <- err
		}
	}(c, dtcp, conn)

	go func(err chan<- error, stcp, dtcp net.Conn) {
		for {
			_, err := io.Copy(stcp, dtcp)
			// if err == nil {
			// 	logger.Infof("send %v bytes from %v to %v", n, dtcp.RemoteAddr().String(), stcp.RemoteAddr().String())
			// }
			c <- err
		}
	}(c, conn, dtcp)

	select {
	case <-stopCh:
	case <-c:
	case err := <-closeCh:
		logger.Infof("close conn: %v", err.Error())
	}

	m.mu.Lock()
	if ls, ok := m.Listeners[port]; ok {
		delete(ls.Conns, remoteaddr)
	}
	m.mu.Unlock()

	logger.Infof("quit conn %v to %v\n", conn.RemoteAddr().String(), dtcp.RemoteAddr().String())
}

func changeIP(args []ChangeIP) error {
	ifn, err := os.Create(interface_path)
	if err != nil {
		return fmt.Errorf("create interfaces failed: %v", err.Error())
	}

	if !writeInterface(ifn) {
		return fmt.Errorf("writeInterface failed")
	}

	for _, item := range args {
		if len(item.Name) <= 0 || strings.Contains(item.Name, "wlan") {
			continue
		}
		_, err = fmt.Fprintln(ifn)
		if err != nil {
			return fmt.Errorf("write config file failed: %v", err.Error())
		}
		_, err = fmt.Fprintln(ifn, fmt.Sprintf("auto %v", item.Name))
		if err != nil {
			return fmt.Errorf("write config file failed: %v", err.Error())
		}
		if item.IsStatic {
			_, err = fmt.Fprintln(ifn, fmt.Sprintf("iface %v inet static", item.Name))
			if err != nil {
				return fmt.Errorf("write config file failed: %v", err.Error())
			}
			_, err = fmt.Fprintln(ifn, fmt.Sprintf("address %v", item.IP))
			if err != nil {
				return fmt.Errorf("write config file failed: %v", err.Error())
			}
			_, err = fmt.Fprintln(ifn, fmt.Sprintf("gateway %v", item.GateWay))
			if err != nil {
				return fmt.Errorf("write config file failed: %v", err.Error())
			}
			_, err = fmt.Fprintln(ifn, fmt.Sprintf("netmask %v", item.Mask))
			if err != nil {
				return fmt.Errorf("write config file failed: %v", err.Error())
			}
		} else {
			_, err = fmt.Fprintln(ifn, fmt.Sprintf("iface %v inet dhcp", item.Name))
			if err != nil {
				return fmt.Errorf("write config file failed: %v", err.Error())
			}
		}
	}
	ifn.Close()

	return exec.Command("reboot").Start()
}

func writeInterface(w io.Writer) bool {
	// header
	_, err := fmt.Fprintln(w, "# /etc/network/interfaces -- configuration file for ifup(8), ifdown(8)")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	// lo
	_, err = fmt.Fprintln(w, "# The loopback interface")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "auto lo")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "iface lo inet loopback")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	// Wireless
	_, err = fmt.Fprintln(w, "iface wlan0 inet dhcp")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "        wireless_mode managed")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "        wireless_essid any")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "        wpa-driver wext")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "        wpa-conf /etc/wpa_supplicant.conf")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	// tiwlan0
	_, err = fmt.Fprintln(w, "iface tiwlan0 inet dhcp")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "        wireless_mode managed")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "        wireless_essid any")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	// atml0
	_, err = fmt.Fprintln(w, "iface atml0 inet dhcp")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	// Wired or wireless
	_, err = fmt.Fprintln(w, "# Wired or wireless interfaces")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "# Ethernet/RNDIS gadget (g_ether)")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "# ... or on host side, usbnet and random hwaddr")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "iface usb0 inet dhcp")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	// bluetooth
	_, err = fmt.Fprintln(w, "# Bluetooth networking")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w, "iface bnep0 inet dhcp")
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		logger.Errorf("write interface failed: %v", err.Error())
		return false
	}

	return true
}

func getInterface() ([]ChangeIP, error) {
	file, err := os.Open(interface_path)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %v", err.Error())
	}
	r, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %v", err.Error())
	}
	file.Close()
	lines := strings.Split(string(r), "\n")

	inf, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read Interfaces failed: %v", err.Error())
	}
	// logger.Infof("interface %+v", inf)
	var result []ChangeIP
	for _, i := range inf {
		if !strings.HasPrefix(i.Name, "e") && !strings.Contains(i.Name, "以") && !strings.Contains(i.Name, "wlan") {
			continue
		}
		for ind, line := range lines {
			if strings.Contains(line, i.Name) && !strings.Contains(line, "auto") && !strings.HasPrefix(line, "#") {
				var cp ChangeIP
				cp.Name = i.Name
				if strings.Contains(line, "dhcp") {
					cp.IsStatic = false
					cp.GateWay = ""
				} else {
					cp.IsStatic = true
					if strings.Contains(lines[ind+1], "gateway") && len(strings.Split(lines[ind+1], " ")) > 0 {
						cp.GateWay = strings.Split(lines[ind+1], " ")[1]
					} else if strings.Contains(lines[ind+2], "gateway") && len(strings.Split(lines[ind+2], " ")) > 0 {
						cp.GateWay = strings.Split(lines[ind+2], " ")[1]
					} else if strings.Contains(lines[ind+3], "gateway") && len(strings.Split(lines[ind+3], " ")) > 0 {
						cp.GateWay = strings.Split(lines[ind+3], " ")[1]
					} else {
						cp.GateWay = ""
					}
				}

				addrs, err := i.Addrs()
				if err != nil {
					return nil, fmt.Errorf("read Addrs failed: %v", err.Error())
				}
				if len(addrs) > 0 {
					if ip, ok := addrs[len(addrs)-1].(*net.IPNet); ok && !ip.IP.IsLoopback() {
						cp.IP = ip.IP.String()
						cp.Mask = ip.Mask.String()
					}
				} else {
					cp.IP = ""
					cp.Mask = ""
				}
				result = append(result, cp)
			}
		}
	}

	return result, nil
}

func isValidIP(ip string) bool {
	ok, err := regexp.MatchString(ipRegexp, ip)
	if err != nil {
		logger.Errorf("check ip(%v) validation failed: %v", ip, err.Error())
		return false
	}
	return ok
}

func copymap(src, dest interface{}) {
	r, _ := json.Marshal(src)
	json.Unmarshal(r, dest)
}

func (m *TopProxy) register() {
	for {
		err, hb := cfgMnager.ReadConfigFile(config_path, "general", "heartbeat")
		if err != nil {
			logger.Errorf("get heartbeat faild: %v", err.Error())
		}
		heartbeat, err := strconv.Atoi(hb)
		if err != nil || heartbeat <= 0 {
			heartbeat = 60 //默认1分钟
		}

		time.Sleep(time.Second * time.Duration(heartbeat))
		if cfgMnager == nil {
			break
		}

		err, master := cfgMnager.ReadConfigFile(config_path, "general", "master")
		if err != nil {
			logger.Errorf("get master addr failed: %v", err.Error())
			continue
		}
		err, name := cfgMnager.ReadConfigFile(config_path, "general", "name")
		if err != nil {
			logger.Errorf("get proxy name failed: %v", err.Error())
			continue
		}
		// err, version := cfgMnager.ReadConfigFile(config_path, "general", "version")
		// if err != nil {
		// 	logger.Errorf("get client version failed: %v", err.Error())
		// 	continue
		// }
		if len(master) <= 0 {
			continue
		}
		if !strings.HasPrefix(master, "http://") {
			master = fmt.Sprintf("http://%v", master)
		}

		info := arm.ModArmArgs{
			IPAddress: m.LocalIP,
			Name:      name,
		}
		b, err := json.Marshal(info)
		if err != nil {
			logger.Errorf("Register Marshal body failed: %v", err.Error())
			continue
		}
		type args struct {
			Oauth string `json:"Oauth"`
			Body  string `json:"Body"`
		}
		pb, err := json.Marshal(args{
			Body: string(b),
		})
		if err != nil {
			logger.Errorf("Register Marshal args failed: %v", err.Error())
			continue
		}

		http.Post(master, "application/json", bytes.NewBuffer(pb))
	}
}
