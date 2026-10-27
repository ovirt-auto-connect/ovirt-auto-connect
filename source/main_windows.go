//go:build windows

package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed EltexRootCA.pem
var embeddedCA []byte

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "\nОшибка:", err)
		fmt.Fprintln(os.Stderr, "Нажмите Enter для закрытия окна...")
		// Only pause for an interactive console. Piped runs must not hang.
		var mode uint32
		if h, e := getConsoleHandle(); e == nil && getConsoleMode(h, &mode) == nil {
			_, _ = inputReader().ReadString('\n')
		}
		os.Exit(1)
	}
}

func run() error {
	var setup, listOnly, choose, clearVM bool
	var vmName, userName, profile, viewerPath, apiURL, caPath string
	var timeoutSec int
	flag.BoolVar(&setup, "setup", false, "Первая настройка / изменение логина, пароля и ВМ")
	flag.BoolVar(&setup, "s", false, "Первая настройка")
	flag.BoolVar(&listOnly, "list", false, "Показать доступные ВМ без подключения")
	flag.BoolVar(&choose, "choose", false, "Выбрать виртуальную машину из списка")
	flag.BoolVar(&clearVM, "clear-vm", false, "Удалить сохранённое имя ВМ; подключаться к первой доступной")
	flag.StringVar(&vmName, "vm", "", "Имя ВМ (сохраняется и выполняется подключение)")
	flag.StringVar(&vmName, "v", "", "Имя ВМ")
	flag.StringVar(&userName, "user", "", "Изменить логин и пароль")
	flag.StringVar(&userName, "u", "", "Изменить логин и пароль")
	flag.StringVar(&profile, "profile", "", "Изменить профиль oVirt")
	flag.StringVar(&profile, "p", "", "Изменить профиль oVirt")
	flag.StringVar(&viewerPath, "remote-viewer", "", "Путь к remote-viewer.exe")
	flag.StringVar(&apiURL, "api-url", defaultAPIURL, "URL API oVirt (HTTPS)")
	flag.StringVar(&caPath, "ca-file", "", "Дополнительный CA-сертификат PEM")
	flag.IntVar(&timeoutSec, "timeout", 300, "Таймаут запуска ВМ (секунды)")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "oVirt Auto Connect для Windows. Запустите двойным щелчком или из PowerShell.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if timeoutSec <= 0 {
		return errors.New("--timeout должен быть положительным")
	}
	if setup {
		return setupInteractive("")
	}
	if clearVM {
		if err := deleteSecret("vm"); err != nil {
			return err
		}
		fmt.Println("Сохранённое имя ВМ удалено. Следующий запуск выберет первую доступную ВМ в порядке ответа oVirt.")
		return nil
	}
	if userName != "" {
		reader := inputReader()
		secret, err := promptPassword(reader, "Пароль для "+userName+": ")
		if err != nil {
			return err
		}
		if secret == "" {
			return errors.New("пароль не может быть пустым")
		}
		if err := saveSecret("user", userName); err != nil {
			return err
		}
		if err := saveSecret("password", secret); err != nil {
			return err
		}
	}
	if profile != "" {
		if err := saveSecret("profile", profile); err != nil {
			return err
		}
	}
	if vmName = strings.TrimSpace(vmName); vmName != "" {
		if err := saveSecret("vm", vmName); err != nil {
			return err
		}
	}
	if userName != "" || profile != "" {
		fmt.Println("Учётные данные обновлены.")
		return nil
	}

	saved := map[string]string{}
	for _, key := range []string{"user", "password", "profile", "vm"} {
		val, err := getSecret(key)
		if err != nil {
			return err
		}
		saved[key] = val
	}
	if saved["user"] == "" || saved["password"] == "" || saved["profile"] == "" {
		fmt.Println("Первый запуск. Настроим подключение к oVirt.")
		if err := setupInteractive(saved["vm"]); err != nil {
			return err
		}
		for _, key := range []string{"user", "password", "profile", "vm"} {
			val, err := getSecret(key)
			if err != nil {
				return err
			}
			saved[key] = val
		}
	}
	ca := embeddedCA
	var err error
	if caPath != "" {
		ca, err = os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("чтение CA-файла: %w", err)
		}
	}
	conn, err := newClient(apiURL, saved["user"], saved["password"], saved["profile"], ca)
	if err != nil {
		return err
	}
	defer conn.close()
	fmt.Printf("Авторизация oVirt: %s\n", conn.username)
	ctx := context.Background()
	if listOnly || choose {
		items, err := conn.listVMs(ctx)
		if err != nil {
			return err
		}
		if listOnly {
			printVMs(items)
			return nil
		}
		selected, err := chooseVM(items)
		if err != nil {
			return err
		}
		saved["vm"] = selected
		if err := saveSecret("vm", selected); err != nil {
			return err
		}
	}
	viewer, err := findViewer(viewerPath)
	if err != nil {
		return err
	}
	if saved["vm"] == "" {
		fmt.Println("Имя ВМ не задано. Выбираю первую доступную ВМ из ответа oVirt.")
	} else {
		fmt.Println("Подключаюсь к ВМ:", saved["vm"])
	}
	file, err := conn.getConnectionFile(ctx, saved["vm"], time.Duration(timeoutSec)*time.Second, func(s string) { fmt.Println(s) })
	var missing *vmNotFoundError
	if errors.As(err, &missing) && len(missing.Available) > 0 {
		fmt.Printf("ВМ %q не найдена. Выберите ВМ из списка доступных:\n", missing.Name)
		selected, selErr := chooseVM(missing.Available)
		if selErr != nil {
			return selErr
		}
		saved["vm"] = selected
		if err := saveSecret("vm", selected); err != nil {
			return err
		}
		fmt.Println("Подключаюсь к ВМ:", selected)
		file, err = conn.getConnectionFile(ctx, selected, time.Duration(timeoutSec)*time.Second, func(s string) { fmt.Println(s) })
	}
	if err != nil {
		return err
	}
	vv, err := os.CreateTemp("", "ovirt-*.vv")
	if err != nil {
		return fmt.Errorf("не удалось создать временный .vv: %w", err)
	}
	defer os.Remove(vv.Name())
	if _, err = vv.WriteString(file); err != nil {
		vv.Close()
		return err
	}
	if err := vv.Close(); err != nil {
		return err
	}
	fmt.Println("Открываю SPICE-консоль...")
	cmd := exec.Command(viewer, vv.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("запуск Virt Viewer: %w", err)
	}
	return nil
}

func setupInteractive(defaultVM string) error {
	r := inputReader()
	username, err := promptLine(r, "Логин oVirt: ")
	if err != nil {
		return err
	}
	if username == "" {
		return errors.New("нужно указать логин")
	}
	password, err := promptPassword(r, "Пароль oVirt: ")
	if err != nil {
		return err
	}
	profile, err := promptLine(r, "Профиль oVirt (например, internal): ")
	if err != nil {
		return err
	}
	vmPrompt := "Имя ВМ (Enter — первая доступная ВМ): "
	if defaultVM != "" {
		vmPrompt = fmt.Sprintf("Имя ВМ (Enter — %s): ", defaultVM)
	}
	vmName, err := promptLine(r, vmPrompt)
	if err != nil {
		return err
	}
	if vmName == "" {
		vmName = defaultVM
	}
	if password == "" || profile == "" {
		return errors.New("пароль и профиль oVirt обязательны")
	}
	for key, value := range map[string]string{"user": username, "password": password, "profile": profile} {
		if err := saveSecret(key, value); err != nil {
			return err
		}
	}
	if vmName == "" {
		if err := deleteSecret("vm"); err != nil {
			return err
		}
	} else {
		if err := saveSecret("vm", vmName); err != nil {
			return err
		}
	}
	fmt.Println("Настройки сохранены в Windows Credential Manager.")
	return nil
}

func findViewer(explicit string) (string, error) {
	candidates := []string{explicit, os.Getenv("OVIRT_REMOTE_VIEWER")}
	if p, err := exec.LookPath("remote-viewer.exe"); err == nil {
		candidates = append(candidates, p)
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		for _, dir := range []string{"VirtViewer", "Virt Viewer", "virt-viewer"} {
			candidates = append(candidates, filepath.Join(base, dir, "bin", "remote-viewer.exe"))
		}
		found, _ := filepath.Glob(filepath.Join(base, "VirtViewer*", "bin", "remote-viewer.exe"))
		candidates = append(candidates, found...)
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if info, err := os.Stat(strings.Trim(path, `"`)); err == nil && !info.IsDir() {
			return strings.Trim(path, `"`), nil
		}
	}
	return "", errors.New("не найден remote-viewer.exe. Установите Virt Viewer для Windows или задайте --remote-viewer \"C:\\...\\remote-viewer.exe\"")
}

func printVMs(items []vm) {
	if len(items) == 0 {
		fmt.Println("Нет доступных виртуальных машин. Проверьте права пользователя в oVirt.")
		return
	}
	fmt.Printf("Доступные виртуальные машины (%d):\n", len(items))
	for i, item := range items {
		fmt.Printf("%3d. %s [%s]\n", i+1, item.Name, item.Status)
	}
}

func chooseVM(items []vm) (string, error) {
	if len(items) == 0 {
		return "", errors.New("список доступных виртуальных машин пуст. Проверьте права в oVirt")
	}
	printVMs(items)
	answer, err := promptLine(inputReader(), "Введите номер ВМ или её полное имя: ")
	if err != nil {
		return "", err
	}
	if index, err := strconv.Atoi(answer); err == nil {
		if index >= 1 && index <= len(items) {
			fmt.Println("Выбрана ВМ:", items[index-1].Name)
			return items[index-1].Name, nil
		}
		return "", errors.New("номер ВМ вне списка")
	}
	item, found, err := matchVM(items, answer)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("ВМ %q отсутствует в списке", answer)
	}
	fmt.Println("Выбрана ВМ:", item.Name)
	return item.Name, nil
}
