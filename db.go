package main

import (
	"database/sql"
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
