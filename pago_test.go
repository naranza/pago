// Naranza Pago, Copyright 2025 Andrea Davanzo and contributors, GPLv3

package pago

import (
	"testing"
	"strings"
)

func TestHash(t *testing.T) {
	password := "mySecretPassword123!"
	
	hash, err := Hash(password, nil)
	t.Logf("Hash %s", hash)
	if err != nil {
		t.Fatalf("Hash() returned error: %v", err)
	}

	if len(hash) == 0 {
		t.Fatal("Hash() returned an empty string")
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash() returned unexpected prefix, got %s", hash)
	}
}

func TestVerify(t *testing.T) {
	password := "TestVerify"
	wrongPassword := "wrongPassword"
	
	hash, err := Hash(password, nil)
	if err != nil {
		t.Fatalf("Hash() returned error: %v", err)
	}

	ok, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify() returned error on correct password: %v", err)
	}
	if !ok {
		t.Error("Verify() failed for correct password")
	}

	ok, err = Verify(wrongPassword, hash)
	if err != nil {
		t.Fatalf("Verify() returned error on wrong password: %v", err)
	}
	if ok {
		t.Error("Verify() succeeded for wrong password")
	}

	_, err = Verify(password, "invalid-hash-format")
	if err == nil {
		t.Error("Verify() did not return error for invalid hash format")
	}
}


func TestVerify_SixParts(t *testing.T) {
	_, err := Verify("password", "$one$two$three$four")
	if err == nil {
		t.Errorf("Verify() expected error for bad parts count, got: %v", err)
	}
}

func TestVerify_StartWith(t *testing.T) {
	_, err := Verify("password", "$one$two$three$four$five")
	if err == nil {
		t.Errorf("Verify() expected error for 'Invalid prefix', got: %v", err)
	}
}

func TestVerify_Version(t *testing.T) {
	_, err := Verify("password", "$argon2id$two$three$four$five")
	if err == nil {
		t.Errorf("Verify() expected error for 'Incompatible version', got: %v", err)
	}
}

func TestVerify_Params(t *testing.T) {
	_, err := Verify("password", "$argon2id$v=19$three$four$five")
	if err == nil {
		t.Errorf("Verify() expected error for 'Invalid params', got: %v", err)
	}
}

func TestVerify_SaltDecode(t *testing.T) {
	_, err := Verify("password", "$argon2id$v=19$m=65536,t=4,p=1$!!!notbase64!!!$c29tZUhhc2g")
	if err == nil || !strings.Contains(err.Error(), "Salt decode error") {
		t.Errorf("Verify() expected error for 'Salt decode error', got: %v", err)
	}
}

func TestVerify_BadHash(t *testing.T) {
	_, err := Verify("password", "$argon2id$v=19$m=65536,t=4,p=1$c29tZVNhbHQ$!!!notbase64!!!")
	if err == nil || !strings.Contains(err.Error(), "Hash decode error") {
		t.Errorf("Verify() expected error for 'Hash decode error', got: %v", err)
	}
}