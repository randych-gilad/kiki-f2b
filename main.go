package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

func main() {
	Fail2banExists()
	// getAllTables()

	a := &Fail2banStatusClient{}
	a.getError()
	slog.Info(fmt.Sprintf("%s{%q:%q,%q:%q}\n", "Fail2banStatusClient", "StatusMessage", a.StatusMessage, "ErrorMessage", a.ErrorMessage))
	Fail2banStart()
	showJails()
	showBans()
}

func Fail2banExists() {
	if _, err := os.Stat("/usr/bin/fail2ban-client"); errors.Is(err, os.ErrNotExist) {
		slog.Warn(err.Error())
	} else {
		slog.Info("fail2ban-client is present on this machine")
	}
}

func Fail2banStart() {
	_ = exec.Command("service", "fail2ban", "start")
	slog.Info("Starting fail2ban")
}

type Fail2banStatusClient struct {
	StatusMessage string
	ErrorMessage  error
}

func (sc *Fail2banStatusClient) getError() {
	message := func() string {
		cmd := exec.Command("fail2ban-client", "status")
		stdout, _ := cmd.CombinedOutput()
		// if err != nil {
		// 	slog.Error(err.Error())
		// }
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
		sc.StatusMessage = ""
		sc.ErrorMessage = errors.New(messageFinal)
	} else {
		sc.StatusMessage = messageFinal
		sc.ErrorMessage = errors.New("")
	}
}

// todos
// fetch fail2ban-server status as struct
// find any log file and try to cast it to struct

// FIX BELOW

// 24-07-06 05:19:07,641 fail2ban.actions        [17562]: NOTICE  [sshd] Ban 125.125.125.125
// 2024-07-06 05:19:07,653 fail2ban.utils          [17562]: ERROR   7fa8a9ec0ea0 -- exec: iptables -w -N f2b-sshd
// iptables -w -A f2b-sshd -j RETURN
// iptables -w -I INPUT -p tcp -m multiport --dports ssh -j f2b-sshd
// 2024-07-06 05:19:07,653 fail2ban.utils          [17562]: ERROR   7fa8a9ec0ea0 -- stderr: 'iptables v1.8.7 (nf_tables):  RULE_APPEND failed (No such file or directory): rule in chain f2b-sshd'
// 2024-07-06 05:19:07,653 fail2ban.utils          [17562]: ERROR   7fa8a9ec0ea0 -- stderr: "iptables v1.8.7 (nf_tables): Couldn't load match `multiport':No such file or directory"
// 2024-07-06 05:19:07,653 fail2ban.utils          [17562]: ERROR   7fa8a9ec0ea0 -- stderr: ''
// 2024-07-06 05:19:07,653 fail2ban.utils          [17562]: ERROR   7fa8a9ec0ea0 -- stderr: "Try `iptables -h' or 'iptables --help' for more information."
// 2024-07-06 05:19:07,654 fail2ban.utils          [17562]: ERROR   7fa8a9ec0ea0 -- returned 2
// 2024-07-06 05:19:07,654 fail2ban.actions        [17562]: ERROR   Failed to execute ban jail 'sshd' action 'iptables-multiport' info 'ActionInfo({'ip': '125.125.125.125', 'family': 'inet4', 'fid': <function Actions.ActionInfo.<lambda> at 0x7fa8aa84c5e0>, 'raw-ticket': <function Actions.ActionInfo.<lambda> at 0x7fa8aa84cca0>})': Error starting action Jail('sshd')/iptables-multiport: 'Script error'
