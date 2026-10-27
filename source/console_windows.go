//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
)

const enableEchoInput uint32 = 0x0004

var procSetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

func promptLine(reader *bufio.Reader, text string) (string, error) {
	fmt.Print(text)
	v, err := reader.ReadString('\n')
	return strings.TrimSpace(v), err
}

func promptPassword(reader *bufio.Reader, text string) (string, error) {
	console, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	var oldMode uint32
	interactive := err == nil && syscall.GetConsoleMode(console, &oldMode) == nil
	if interactive {
		ok, _, _ := procSetConsoleMode.Call(uintptr(console), uintptr(oldMode&^enableEchoInput))
		if ok == 0 {
			return "", fmt.Errorf("не удалось скрыть ввод пароля в терминале Windows")
		}
		defer procSetConsoleMode.Call(uintptr(console), uintptr(oldMode))
	} else {
		return "", fmt.Errorf("для ввода пароля запустите программу в консоли Windows")
	}
	fmt.Print(text)
	password, readErr := reader.ReadString('\n')
	fmt.Println()
	return strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r"), readErr
}

func inputReader() *bufio.Reader { return bufio.NewReader(os.Stdin) }
