package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

func main() {
	Fail2banExists()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	slog.SetDefault(logger)
	a := NewFail2banStatus()
	Fail2banStart()
	if a.ErrorMessage.Error() != "" {
		logger.Error("Fail2banStatus",
			slog.String("StatusMessage", a.StatusMessage),
			slog.String("ErrorMessage", a.ErrorMessage.Error()))
	} else {
		logger.Info("Fail2banStatus",
			slog.String("StatusMessage", a.StatusMessage),
			slog.String("ErrorMessage", a.ErrorMessage.Error()))
	}
	db, err := newConn(file)
	if err != nil {
		slog.Error("DB connection error",
			slog.String("Error", err.Error()))
	}
	getAllTables(db)
	showJails(db)
	showBans(db)
	showBips(db)
}

func Fail2banExists() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	slog.SetDefault(logger)
	if _, err := os.Stat("/usr/bin/fail2ban-client"); errors.Is(err, os.ErrNotExist) {
		logger.Error(err.Error())
	} else {
		logger.Info("fail2ban-client is present on this machine")
	}
}

func Fail2banStart() {
	cmd := exec.Command("service", "fail2ban", "start")
	cmd.Run()
	slog.Info("Starting fail2ban")
}

type Fail2banStatus struct {
	StatusMessage string
	ErrorMessage  error
}

func NewFail2banStatus() *Fail2banStatus {
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
		return &Fail2banStatus{
			StatusMessage: "",
			ErrorMessage:  errors.New(messageFinal),
		}
	} else {
		return &Fail2banStatus{
			StatusMessage: messageFinal,
			ErrorMessage:  errors.New(""),
		}
	}
}
