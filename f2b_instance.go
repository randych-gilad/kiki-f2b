package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

type Fail2banInstance struct {
	StatusMessage string
	ErrorMessage  error
}

func (i *Fail2banInstance) IsExist() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	slog.SetDefault(logger)
	if _, err := os.Stat("/usr/bin/fail2ban-client"); errors.Is(err, os.ErrNotExist) {
		logger.Error(err.Error())
	} else {
		logger.Info("fail2ban-client is present on this machine")
	}
}

func (i *Fail2banInstance) Start() {
	_ = exec.
		Command("service", "fail2ban", "start").
		Run()
	slog.Info("Starting fail2ban")
}

func (i *Fail2banInstance) Status() {
	message := func() string {
		cmd := exec.Command("fail2ban-client", "status")
		stdout, _ := cmd.CombinedOutput()
		return string(stdout)
	}()
	messageFinal := func() string {
		m := strings.Split(message, "ERROR")
		if len(m) > 1 {
			for i := range m {
				m[i] = strings.TrimSpace(m[i])
			}
			return m[1]
		}
		return message
	}()
	if strings.Contains(messageFinal, "Failed") {
		i.StatusMessage = ""
		i.ErrorMessage = errors.New(messageFinal)
	} else {
		i.StatusMessage = messageFinal
		i.ErrorMessage = errors.New("")
	}
}
