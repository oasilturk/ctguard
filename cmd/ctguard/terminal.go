package main

import "os"

// ANSI color codes
type colors struct {
	Reset   string
	Bold    string
	Red     string
	Green   string
	Yellow  string
	Blue    string
	Magenta string
	Cyan    string
	Gray    string
	Orange  string
}

var noColors = colors{}

var ansiColors = colors{
	Reset:   "\033[0m",
	Bold:    "\033[1m",
	Red:     "\033[31m",
	Green:   "\033[32m",
	Yellow:  "\033[33m",
	Blue:    "\033[34m",
	Magenta: "\033[35m",
	Cyan:    "\033[36m",
	Gray:    "\033[90m",
	Orange:  "\033[38;5;208m",
}

var c colors

func isTerminal() bool {
	if fi, err := os.Stdout.Stat(); err == nil {
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return false
}
