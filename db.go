package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

const file string = "/var/lib/fail2ban/fail2ban.sqlite3"

func newConn(file string) (*dbConn, error) {
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		return nil, err
	}
	return &dbConn{
		mutex: sync.RWMutex{},
		conn:  db,
	}, nil
}

func getAllTables(db *dbConn) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	rows, err := db.conn.Query("SELECT name FROM sqlite_master WHERE type='table';")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			log.Fatal(err)
		}
		tables = append(tables, table)
	}

	if err := rows.Err(); err != nil {
		panic(err)
	}

	for _, table := range tables {
		// fmt.Printf("Table: %s\n", table)

		colRows, err := db.conn.Query(fmt.Sprintf("PRAGMA table_info(%s);", table))
		if err != nil {
			panic(err)
		}
		defer colRows.Close()

		for colRows.Next() {
			var cid int
			var name, ctype string
			var notnull, dfltValue, pk interface{}
			if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				panic(err)
			}
			// fmt.Printf("  Column: %s, Type: %s\n", name, ctype)
		}

		if err := colRows.Err(); err != nil {
			panic(err)
		}
	}
}

func attrSettings(_ []string, a slog.Attr) slog.Attr {
	// This is *temporary*
	if a.Key == "source" {
		// src := a.Value.Any().(*slog.Source)
		// return slog.Group("source", slog.String("function", src.Function), slog.Int("line", src.Line))
		return slog.Attr{}
	}
	// There should be timestamp, but it takes too much space
	// for now
	if a.Key == "time" {
		return slog.Attr{}
	}
	return a
}

func getJails(db *dbConn) ([]Jail, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	rows, err := db.conn.Query("SELECT name, enabled FROM jails")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jails []Jail
	for rows.Next() {
		var jail Jail
		if err := rows.Scan(&jail.Name, &jail.Enabled); err != nil {
			return nil, err
		}
		jails = append(jails, jail)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return jails, nil
}

func showJails(db *dbConn) {
	jails, err := getJails(db)
	if err != nil {
		slog.Error(err.Error())
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	slog.SetDefault(logger)

	for _, j := range jails {
		logger.Info("Jail",
			slog.String("Name", j.Name),
			slog.Int("Enabled", j.Enabled),
		)
	}
}

func getBans(db *dbConn) ([]Ban, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	rows, err := db.conn.Query("SELECT jail, ip, timeofban, bantime, bancount, data FROM bans")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bans []Ban
	for rows.Next() {
		var ban Ban
		var rawData []byte
		if err := rows.Scan(&ban.Jail, &ban.IP, &ban.TimeOfBan, &ban.BanTime, &ban.BanCount, &rawData); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(rawData, &ban.Data); err != nil {
			return nil, err
		}
		bans = append(bans, ban)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bans, nil
}

func showBans(db *dbConn) {
	b, err := getBans(db)
	if err != nil {
		slog.Error(err.Error())
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	slog.SetDefault(logger)
	for _, ban := range b {
		logger.Info("Ban",
			slog.String("Jail", ban.Jail),
			slog.String("IP", ban.IP),
			slog.Int("TimeOfBan", ban.TimeOfBan),
			slog.Int("BanTime", ban.BanTime),
			slog.Int("BanCount", ban.BanCount),
			slog.Group("Data", slog.Any("Matches", ban.Data.Matches), slog.Int("Failures", ban.Data.Failures)),
		)
	}
}

func getBips(db *dbConn) ([]Bip, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	rows, err := db.conn.Query("SELECT ip, jail, timeofban, bantime, bancount, data FROM bips")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bips []Bip
	for rows.Next() {
		var bip Bip
		var rawData []byte
		if err := rows.Scan(&bip.IP, &bip.Jail, &bip.TimeOfBan, &bip.BanTime, &bip.BanCount, &rawData); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(rawData, &bip.Data); err != nil {
			return nil, err
		}
		bips = append(bips, bip)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bips, nil
}

func showBips(db *dbConn) {
	_, err := getBips(db)
	if err != nil {
		slog.Error(err.Error())
	}

	// logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, ReplaceAttr: attrSettings}))
	// slog.SetDefault(logger)
	// for _, bip := range b {
	// 	logger.Info("Bip",
	// 		slog.String("IP", bip.IP),
	// 		slog.String("Jail", bip.Jail),
	// 		slog.Int("TimeOfBan", bip.TimeOfBan),
	// 		slog.Int("BanTime", bip.BanTime),
	// 		slog.Int("BanCount", bip.BanCount),
	// 		slog.Group("Data", slog.Any("Matches", bip.Data.Matches), slog.Int("Failures", bip.Data.Failures)),
	// 	)
	// }
}
