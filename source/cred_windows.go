//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	credNotFound            = syscall.Errno(1168)
	credNamespace           = "ovirt-auto-connect-windows/"
)

type filetime struct{ Low, High uint32 }
type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi         = syscall.NewLazyDLL("advapi32.dll")
	procCredRead   = advapi.NewProc("CredReadW")
	procCredWrite  = advapi.NewProc("CredWriteW")
	procCredDelete = advapi.NewProc("CredDeleteW")
	procCredFree   = advapi.NewProc("CredFree")
)

func saveSecret(key, value string) error {
	target, err := syscall.UTF16PtrFromString(credNamespace + key)
	if err != nil {
		return err
	}
	// Generic CredentialBlob accepts arbitrary UTF-8 bytes, protected by Windows Credential Manager.
	blob := []byte(value)
	c := winCredential{Type: credTypeGeneric, TargetName: target, Persist: credPersistLocalMachine, CredentialBlobSize: uint32(len(blob))}
	if len(blob) != 0 {
		c.CredentialBlob = &blob[0]
	}
	ok, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&c)), 0)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(target)
	if ok == 0 {
		return fmt.Errorf("сохранение %s в Windows Credential Manager: %w", key, callErr)
	}
	return nil
}

func getSecret(key string) (string, error) {
	target, err := syscall.UTF16PtrFromString(credNamespace + key)
	if err != nil {
		return "", err
	}
	var p *winCredential
	ok, _, callErr := procCredRead.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&p)))
	runtime.KeepAlive(target)
	if ok == 0 {
		if errors.Is(callErr, credNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("чтение %s из Windows Credential Manager: %w", key, callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(p)))
	if p.CredentialBlobSize == 0 {
		return "", nil
	}
	if p.CredentialBlob == nil {
		return "", fmt.Errorf("отсутствует содержимое %s", key)
	}
	blob := unsafe.Slice(p.CredentialBlob, int(p.CredentialBlobSize))
	return string(blob), nil
}

func deleteSecret(key string) error {
	target, err := syscall.UTF16PtrFromString(credNamespace + key)
	if err != nil {
		return err
	}
	ok, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	runtime.KeepAlive(target)
	if ok == 0 && !errors.Is(callErr, credNotFound) {
		return fmt.Errorf("удаление %s из Windows Credential Manager: %w", key, callErr)
	}
	return nil
}
