package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid username - lowercase",
			username: "alice",
			wantErr:  false,
		},
		{
			name:     "valid username - uppercase",
			username: "ALICE",
			wantErr:  false,
		},
		{
			name:     "valid username - mixed case",
			username: "AliceSmith",
			wantErr:  false,
		},
		{
			name:     "valid username - with underscore",
			username: "alice_smith",
			wantErr:  false,
		},
		{
			name:     "valid username - with numbers",
			username: "alice123",
			wantErr:  false,
		},
		{
			name:     "valid username - all numbers",
			username: "123456",
			wantErr:  false,
		},
		{
			name:     "valid username - max length",
			username: "a1234567890123456789012345678901", // 32 символа
			wantErr:  false,
		},
		{
			name:     "invalid - empty username",
			username: "",
			wantErr:  true,
			errMsg:   "username cannot be empty",
		},
		{
			name:     "invalid - too short (2 chars)",
			username: "ab",
			wantErr:  true,
			errMsg:   "must be at least 3 characters",
		},
		{
			name:     "invalid - too long (33 chars)",
			username: "a12345678901234567890123456789012", // 33 символа
			wantErr:  true,
			errMsg:   "must not exceed 32 characters",
		},
		{
			name:     "invalid - with dot",
			username: "alice.smith",
			wantErr:  true,
			errMsg:   "can only contain letters",
		},
		{
			name:     "invalid - with dash",
			username: "alice-smith",
			wantErr:  true,
			errMsg:   "can only contain letters",
		},
		{
			name:     "invalid - with space",
			username: "alice smith",
			wantErr:  true,
			errMsg:   "can only contain letters",
		},
		{
			name:     "invalid - with @ symbol",
			username: "alice@email",
			wantErr:  true,
			errMsg:   "can only contain letters",
		},
		{
			name:     "invalid - with special characters",
			username: "alice!@#",
			wantErr:  true,
			errMsg:   "can only contain letters",
		},
		{
			name:     "invalid - cyrillic characters",
			username: "алиса",
			wantErr:  true,
			errMsg:   "can only contain letters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid password - exactly 12 chars",
			password: "password1234",
			wantErr:  false,
		},
		{
			name:     "valid password - long",
			password: "super_secret_password_123",
			wantErr:  false,
		},
		{
			name:     "valid password - with special chars",
			password: "P@ssw0rd!@#$",
			wantErr:  false,
		},
		{
			name:     "valid password - unicode",
			password: "пароль12345678",
			wantErr:  false,
		},
		{
			name:     "invalid - empty password",
			password: "",
			wantErr:  true,
			errMsg:   "password cannot be empty",
		},
		{
			name:     "invalid - too short (11 chars)",
			password: "password123", // 11 символов
			wantErr:  true,
			errMsg:   "must be at least 12 characters",
		},
		{
			name:     "invalid - too short (1 char)",
			password: "p",
			wantErr:  true,
			errMsg:   "must be at least 12 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
