package main

type Fail2banDb struct {
	Version int `json:"version"`
}

type Jail struct {
	Name    string `json:"name"`
	Enabled int    `json:"enabled"`
}

type Log struct {
	Jail         string `json:"jail"`
	Path         string `json:"path"`
	FirstLineMD5 string `json:"firstlinemd5"`
	LastFilePos  int    `json:"lastfilepos"`
}

type Ban struct {
	Jail      string  `json:"jail"`
	IP        string  `json:"ip"`
	TimeOfBan int     `json:"timeofban"`
	BanTime   int     `json:"bantime"`
	BanCount  int     `json:"bancount"`
	Data      BanData `json:"data"`
}
type BanData struct {
	Matches  []string `json:"matches"`
	Failures int      `json:"failures"`
}

type Bip struct {
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	TimeOfBan int    `json:"timeofban"`
	BanTime   int    `json:"bantime"`
	BanCount  int    `json:"bancount"`
	Data      string `json:"data"`
}
