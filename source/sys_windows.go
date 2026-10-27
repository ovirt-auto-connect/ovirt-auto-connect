//go:build windows

package main

import "syscall"

func getConsoleHandle() (syscall.Handle, error) {
	return syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
}
func getConsoleMode(h syscall.Handle, p *uint32) error { return syscall.GetConsoleMode(h, p) }
