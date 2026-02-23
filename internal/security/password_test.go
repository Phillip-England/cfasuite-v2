package security

import "testing"

func TestHashPasswordRequiresMinimumLength(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatalf("expected error for short password")
	}
}

func TestHashPasswordAndVerify(t *testing.T) {
	password := "this-is-a-long-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !VerifyPassword(password, hash) {
		t.Fatalf("expected password verification to succeed")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Fatalf("expected wrong password verification to fail")
	}
}

func TestHashPINAndVerify(t *testing.T) {
	pin := "123456"
	hash, err := HashPIN(pin)
	if err != nil {
		t.Fatalf("hash pin: %v", err)
	}
	if !VerifyPassword(pin, hash) {
		t.Fatalf("expected pin verification to succeed")
	}
	if VerifyPassword("654321", hash) {
		t.Fatalf("expected wrong pin verification to fail")
	}
}
