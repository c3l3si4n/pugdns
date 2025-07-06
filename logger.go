package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

func LogLevelFromString(s string) LogLevel {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN":
		return WARN
	case "ERROR":
		return ERROR
	case "FATAL":
		return FATAL
	default:
		return INFO // Default level
	}
}

var (
	colorDebug   = color.New(color.FgMagenta).SprintFunc()
	colorInfo    = color.New(color.FgHiBlue).SprintFunc()
	colorSuccess = color.New(color.FgGreen).SprintFunc()
	colorWarn    = color.New(color.FgYellow).SprintFunc()
	colorError   = color.New(color.FgRed).SprintFunc()
	colorFatal   = color.New(color.FgRed, color.Bold).SprintFunc()
)

type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level LogLevel
	log   *log.Logger
}

func NewLogger(out io.Writer, level LogLevel) *Logger {
	return &Logger{
		out:   out,
		level: level,
		log:   log.New(out, "", 0), // No prefix, we handle it ourselves
	}
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) print(level LogLevel, colorFunc func(a ...interface{}) string, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.level <= level {
		timestamp := time.Now().Format("15:04:05.000")
		levelStr := colorFunc(fmt.Sprintf("[%s]", level.String()))
		message := fmt.Sprintf(format, args...)
		l.log.Printf("%s %s %s", levelStr, timestamp, message)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.print(DEBUG, colorDebug, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.print(INFO, colorInfo, format, args...)
}

func (l *Logger) Success(format string, args ...interface{}) {
	l.print(INFO, colorSuccess, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.print(WARN, colorWarn, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.print(ERROR, colorError, format, args...)
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.print(FATAL, colorFatal, format, args...)
	os.Exit(1)
}

// Global logger instance
var appLogger *Logger

func init() {
	// Initialize with default values. Will be configured in main.
	appLogger = NewLogger(os.Stderr, INFO)
}
