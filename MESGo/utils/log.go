package utils

import (
	"os"
	"github.com/omidnikta/logrus"
)

var Logger = logrus.New()

//SetLog 设置log文件及格式,日志 用linux Logrotate
func SetLog(loglevel string, logfile string) error {
	Logger.Formatter = new(logrus.JSONFormatter)
	Logger.Level = logrus.DebugLevel
	// logg.SetFormatter(&logg.JSONFormatter{})
	var f *os.File
	var err error
	if f, err = os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
		panic(err)
	}
	switch loglevel {
	case "Debug":
		Logger.Level = logrus.DebugLevel
	case "Info":
		Logger.Level = logrus.InfoLevel
	case "Warn":
		Logger.Level = logrus.WarnLevel
	case "Error":
		Logger.Level = logrus.ErrorLevel
	default:
		Logger.Level = logrus.InfoLevel
	}
	Logger.Out = f
	return nil
}

// func init() {
// 	cfg, err := ini.Load("config.ini")
// 	if err != nil {
// 		panic(err)
// 	}
// 	loglevel := cfg.Section("log").Key("level").String()
// 	logfile := cfg.Section("log").Key("filename").String()
// 	SetLog(loglevel, logfile)
// }

// func NewLogger() *logrus.Logger {
// 	_, file, _, ok := runtime.Caller(1)
// 	if !ok {
// 		file = "unknown"
// 	}
// 	ret := logrus.New()
// 	logrus.SetFormatter(&logrus.JSONFormatter{})
// 	var f *os.File
// 	var err error
// 	if f, err = os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
// 		panic(err)
// 	}
// 	logrus.SetOutput(f)
// 	inst := &logInstance{
// 		innerLogger: ret,
// 		file:        filepath.Base(file),
// 	}
// 	ret.Hooks.Add(inst)
// 	return ret
// }
