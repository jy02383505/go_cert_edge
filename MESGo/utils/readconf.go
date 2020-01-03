package utils

import (
	"fmt"
	// "time"

	r "gopkg.in/ini.v1"
)

var ServerPort = 51108
var Read_time_out = 30
var CENTERIP = "127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1"
var CENTERPORT = 8001
var FILESAVEPATH = "/home/lhh/cert"

func init() {
	// cfg, err := r.Load("/usr/local/goMES/config.ini") // online env
	// cfg, err := r.Load("/usr/local/preload/src/go/preloadgo/config.ini") // online env old
	cfg, err := r.Load("config.ini") // for local
	if err != nil {
		panic(err)
	}
	loglevel := cfg.Section("log").Key("level").String()
	logfile := cfg.Section("log").Key("filename").String()
	// logfile = fmt.Sprintf("%s/%s", "logs", logfile)
	SetLog(loglevel, logfile)
	ServerPort, err = cfg.Section("server").Key("ServerPort").Int()
	//Head = cfg.Section("server").Key("head").String()
	Read_time_out, err = cfg.Section("server").Key("read_time_out").Int()
	CENTERIP = cfg.Section("server").Key("CENTERIP").String()
	CENTERPORT,err = cfg.Section("server").Key("CENTERPORT").Int()
	FILESAVEPATH = cfg.Section("server").Key("FILESAVEPATH").String()
	fmt.Printf("CENTERPORT: %d\nServerPort: %d\nFILESAVEPATH: %s\nRead_time_out: %d\nCENTERIP: %s\nInitializationWithNothingWrong->server is running...", CENTERPORT, ServerPort, FILESAVEPATH, Read_time_out, CENTERIP)

}
