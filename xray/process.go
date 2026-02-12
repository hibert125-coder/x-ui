package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/hibert125-coder/x-ui/config"
	"github.com/hibert125-coder/x-ui/logger"
	"github.com/hibert125-coder/x-ui/util/common"
)

func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

func GetConfigPath() string {
	return config.GetBinFolderPath() + "/config.json"
}

func GetGeositePath() string {
	return config.GetBinFolderPath() + "/geosite.dat"
}

func GetGeoipPath() string {
	return config.GetBinFolderPath() + "/geoip.dat"
}

func stopProcess(p *Process) {
	p.Stop()
}

type Process struct {
	*process
}

func NewProcess(xrayConfig *Config) *Process {
	p := &Process{newProcess(xrayConfig)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

type process struct {
	cmd *exec.Cmd

	version string
	apiPort int

	onlineClients []string

	api *XrayAPI

	config    *Config
	logWriter *LogWriter
	exitErr   error
	startTime time.Time
}

func newProcess(config *Config) *process {
	return &process{
		version:   "Unknown",
		config:    config,
		logWriter: NewLogWriter(),
		startTime: time.Now(),
	}
}

func (p *process) IsRunning() bool {
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	if p.cmd.ProcessState == nil {
		return true
	}
	return false
}

func (p *process) GetErr() error {
	return p.exitErr
}

func (p *process) GetResult() string {
	if len(p.logWriter.lastLine) == 0 && p.exitErr != nil {
		return p.exitErr.Error()
	}
	return p.logWriter.lastLine
}

func (p *process) GetVersion() string {
	return p.version
}

func (p *Process) GetAPIPort() int {
	return p.apiPort
}

func (p *Process) GetConfig() *Config {
	return p.config
}

func (p *Process) GetOnlineClients() []string {
	return p.onlineClients
}
func (p *Process) SetOnlineClients(users []string) {
	if p.config == nil {
		p.onlineClients = users
		return
	}

	var filtered []string
	counter := make(map[string]int)

	for _, email := range users {

		counter[email]++

		allowed := true

		for _, inbound := range p.config.InboundConfigs {

			var settings struct {
				Clients []struct {
					Email          string `json:"email"`
					MaxConnections int    `json:"maxConnections"`
				} `json:"clients"`
			}

			if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
				continue
			}

			for _, client := range settings.Clients {
				if client.Email == email {

					if client.MaxConnections > 0 && counter[email] > client.MaxConnections {
						logger.Warning("Reject extra connection:", email)
						allowed = false
					}

					break
				}
			}
		}

		if allowed {
			filtered = append(filtered, email)
		}
	}

	p.onlineClients = filtered
}

func (p *Process) GetUptime() uint64 {
	return uint64(time.Since(p.startTime).Seconds())
}

func (p *process) refreshAPIPort() {
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			p.apiPort = inbound.Port
			break
		}
	}
}

func (p *process) refreshVersion() {
	cmd := exec.Command(GetBinaryPath(), "-version")
	data, err := cmd.Output()
	if err != nil {
		p.version = "Unknown"
	} else {
		datas := bytes.Split(data, []byte(" "))
		if len(datas) <= 1 {
			p.version = "Unknown"
		} else {
			p.version = string(datas[1])
		}
	}
}

func (p *process) Start() (err error) {
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			logger.Error("Failure in running xray-core process: ", err)
			p.exitErr = err
		}
	}()

	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return common.NewErrorf("Failed to generate XRAY configuration files: %v", err)
	}
	configPath := GetConfigPath()
	err = os.WriteFile(configPath, data, fs.ModePerm)
	if err != nil {
		return common.NewErrorf("Write the configuration file failed: %v", err)
	}
	cmd := exec.Command(GetBinaryPath(), "-c", configPath)
	p.cmd = cmd

	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter

	go func() {
		err := cmd.Run()
		if err != nil {
			logger.Error("Failure in running xray-core: ", err)
			p.exitErr = err
		}
	}()

	p.refreshVersion()
	p.refreshAPIPort()

	api := &XrayAPI{}
	if err := api.Init(p.apiPort); err == nil {
		p.api = api
		logger.Info("Xray API connected")
		p.startLimiter()
	} else {
		logger.Warning("Failed to connect Xray API:", err)
	}

	return nil

}

func (p *process) Stop() error {
	if !p.IsRunning() {
		return errors.New("xray is not running")
	}

	if runtime.GOOS == "windows" {
		return p.cmd.Process.Kill()
	} else {
		return p.cmd.Process.Signal(syscall.SIGTERM)
	}
}
func (p *process) startLimiter() {
	go func() {
		for {
			time.Sleep(5 * time.Second)

			if p.api == nil || p.config == nil {
				continue
			}

			onlineUsers, err := p.api.GetOnlineUsers()
			if err != nil {
				logger.Warning("Limiter: cannot get online users")
				continue
			}

			counter := make(map[string]int)

			for _, email := range onlineUsers {
				counter[email]++
			}

			for _, inbound := range p.config.InboundConfigs {

				var settings struct {
					Clients []struct {
						Email          string `json:"email"`
						MaxConnections int    `json:"maxConnections"`
					} `json:"clients"`
				}

				if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
					continue
				}

				for _, client := range settings.Clients {

					if client.MaxConnections == 0 {
						continue
					}

					if counter[client.Email] > client.MaxConnections {

						logger.Warning("Kicking extra connection:", client.Email)

						_ = p.api.RemoveUser(inbound.Tag, client.Email)
					}
				}
			}
		}
	}()
}

func writeCrashReport(m []byte) error {
	crashReportPath := config.GetBinFolderPath() + "/core_crash_" + time.Now().Format("20060102_150405") + ".log"
	return os.WriteFile(crashReportPath, m, os.ModePerm)
}
