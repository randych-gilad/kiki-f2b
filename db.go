package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"

	_ "github.com/mattn/go-sqlite3"
)

const file string = "/var/lib/fail2ban/fail2ban.sqlite3"

func getAllTables() {
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Get the list of tables
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table';")
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
		fmt.Printf("Table: %s\n", table)

		colRows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s);", table))
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
			fmt.Printf("  Column: %s, Type: %s\n", name, ctype)
		}

		if err := colRows.Err(); err != nil {
			panic(err)
		}
	}
}

func getJails(db *sql.DB) ([]Jail, error) {
	rows, err := db.Query("SELECT name, enabled FROM jails")
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

func showJails() {
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	j, err := getJails(db)
	if err != nil {
		slog.Error(err.Error())
	}
	for _, jail := range j {
		slog.Info(fmt.Sprintf("%s{%q: %q, %q: %d}\n", "Jail", "Name", jail.Name, "Enabled", jail.Enabled))
	}
}

func getBans(db *sql.DB) ([]Ban, error) {
	rows, err := db.Query("SELECT jail, ip, timeofban, bantime, bancount, data FROM bans")
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

func showBans() {
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	b, err := getBans(db)
	if err != nil {
		slog.Error(err.Error())
	}
	for _, ban := range b {
		slog.Info(fmt.Sprintf("%s{%q: %q, %q: %q, %q: %d, %q: %d, %q: %d, %s{%q: %q, %q: %d}}\n",
			"Ban", "Jail", ban.Jail, "IP", ban.IP, "TimeOfBan", ban.TimeOfBan, "BanTime", ban.BanTime, "BanCount", ban.BanCount, "Data", "Matches", ban.Data.Matches, "Failures", ban.Data.Failures))
	}
}
