package main

import (
	"log/slog"
	"os"
)

func main() {
	inst := &Fail2banInstance{}
	inst.IsExist()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	slog.SetDefault(logger)
	inst.Start()
	inst.Status()
	if inst.ErrorMessage.Error() != "" {
		logger.Error("Fail2banStatus",
			slog.String("StatusMessage", inst.StatusMessage),
			slog.String("ErrorMessage", inst.ErrorMessage.Error()))
	} else {
		logger.Info("Fail2banStatus",
			slog.String("StatusMessage", inst.StatusMessage),
			slog.String("ErrorMessage", inst.ErrorMessage.Error()))
	}
	db, err := newConn(file)
	if err != nil {
		slog.Error("DB connection error",
			slog.String("Error", err.Error()))
	}
	db.getAllTables()
	db.showJails()
	db.showBans()
	db.showBips()
}
