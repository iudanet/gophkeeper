package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetMasterPassword_FromEnvVar проверяет чтение пароля из переменной окружения
func TestGetMasterPassword_FromEnvVar(t *testing.T) {
	// Setup
	cli := &Cli{}
	testPassword := "test_env_password_123"
	require.NoError(t, os.Setenv("GOPHKEEPER_MASTER_PASSWORD", testPassword))
	defer func() {
		require.NoError(t, os.Unsetenv("GOPHKEEPER_MASTER_PASSWORD"))
	}()
	passwords := Passwors{
		FromFile: "",
		FromArgs: "",
	}
	// Execute
	password, err := cli.getMasterPassword(passwords)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, testPassword, password)
}

// TestGetMasterPassword_FromFile проверяет чтение пароля из файла
func TestGetMasterPassword_FromFile(t *testing.T) {
	// Setup
	cli := &Cli{}
	testPassword := "test_file_password_456"

	// Создаем временный файл с паролем
	tmpfile, err := os.CreateTemp("", "password-*.txt")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()

	_, err = tmpfile.WriteString(testPassword + "\n")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	passwords := Passwors{
		FromFile: tmpfile.Name(),
		FromArgs: "",
	}
	// Execute
	password, err := cli.getMasterPassword(passwords)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, testPassword, password)
}

// TestGetMasterPassword_FromCLIParam проверяет чтение пароля из CLI параметра
func TestGetMasterPassword_FromCLIParam(t *testing.T) {
	// Setup
	cli := &Cli{}
	pass := Passwors{
		FromFile: "",
		FromArgs: "test_cli_password_789",
	}
	// Execute
	password, err := cli.getMasterPassword(pass)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, pass.FromArgs, password)
}

// TestGetMasterPassword_Priority проверяет приоритет источников
// Env var должен иметь приоритет над файлом и CLI параметром
func TestGetMasterPassword_Priority(t *testing.T) {
	// Setup
	cli := &Cli{}
	envPassword := "env_password"
	filePassword := "file_password"
	cliPassword := "cli_password"

	// Создаем файл
	tmpfile, err := os.CreateTemp("", "password-*.txt")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()
	_, err = tmpfile.WriteString(filePassword)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	// Устанавливаем env var
	require.NoError(t, os.Setenv("GOPHKEEPER_MASTER_PASSWORD", envPassword))
	defer func() {
		require.NoError(t, os.Unsetenv("GOPHKEEPER_MASTER_PASSWORD"))
	}()
	pass := Passwors{
		FromFile: tmpfile.Name(),
		FromArgs: cliPassword,
	}
	// Execute - передаем все источники
	password, err := cli.getMasterPassword(pass)

	// Assert - должен вернуться env var (наивысший приоритет)
	require.NoError(t, err)
	assert.Equal(t, envPassword, password)
}

// TestGetMasterPassword_FileOverCLI проверяет что файл имеет приоритет над CLI
func TestGetMasterPassword_FileOverCLI(t *testing.T) {
	// Setup
	cli := &Cli{}
	filePassword := "file_password_priority"
	cliPassword := "cli_password_lower"

	// Создаем файл
	tmpfile, err := os.CreateTemp("", "password-*.txt")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()
	_, err = tmpfile.WriteString(filePassword)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	pass := Passwors{
		FromFile: tmpfile.Name(),
		FromArgs: cliPassword,
	}
	// Execute - env var НЕ установлен, передаем файл и CLI
	password, err := cli.getMasterPassword(pass)

	// Assert - должен вернуться файл (приоритет 2)
	require.NoError(t, err)
	assert.Equal(t, filePassword, password)
}

// TestGetMasterPassword_EmptyFile проверяет обработку пустого файла
func TestGetMasterPassword_EmptyFile(t *testing.T) {
	// Setup
	cli := &Cli{}

	// Создаем пустой файл
	tmpfile, err := os.CreateTemp("", "password-*.txt")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()
	require.NoError(t, tmpfile.Close())
	pass := Passwors{
		FromFile: tmpfile.Name(),
		FromArgs: "",
	}
	// Execute
	password, err := cli.getMasterPassword(pass)

	// Assert - должна быть ошибка
	require.Error(t, err)
	assert.Empty(t, password)
	assert.Contains(t, err.Error(), "password file is empty")
}

// TestGetMasterPassword_FileNotFound проверяет обработку несуществующего файла
func TestGetMasterPassword_FileNotFound(t *testing.T) {
	// Setup
	cli := &Cli{}
	pass := Passwors{
		FromFile: "/nonexistent/file/path.txt",
		FromArgs: "",
	}
	// Execute
	password, err := cli.getMasterPassword(pass)

	// Assert - должна быть ошибка
	require.Error(t, err)
	assert.Empty(t, password)
	assert.Contains(t, err.Error(), "failed to read password file")
}

// TestGetMasterPassword_FileWithWhitespace проверяет что whitespace обрезается
func TestGetMasterPassword_FileWithWhitespace(t *testing.T) {
	// Setup
	cli := &Cli{}
	testPassword := "password_with_spaces"

	// Создаем файл с пробелами и переводами строк
	tmpfile, err := os.CreateTemp("", "password-*.txt")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()
	_, err = tmpfile.WriteString("  " + testPassword + "  \n\n")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	pass := Passwors{
		FromFile: tmpfile.Name(),
		FromArgs: "",
	}
	// Execute
	password, err := cli.getMasterPassword(pass)

	// Assert - пробелы должны быть обрезаны
	require.NoError(t, err)
	assert.Equal(t, testPassword, password)
}
