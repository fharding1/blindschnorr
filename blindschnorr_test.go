package blindschnorr

import (
	"encoding/base64"
	rand "math/rand/v2"
	"testing"

	_ "github.com/gtank/ristretto255"
)

func Correctness(message []byte) (bool, error) {
	src := rand.NewChaCha8([32]byte{})
	sk, err := GenerateKey(src)
	if err != nil {
		return false, err
	}
	pk := sk.Public().(*PublicKey)

	ss := sk.NewSignerState()

	cmt, err := ss.NewCommitment()
	if err != nil {
		return false, err
	}

	us := pk.NewUserState()

	chal, err := us.NewChallenge(cmt, message)
	if err != nil {
		return false, err
	}

	rsp, err := ss.NewResponse(chal)
	if err != nil {
		return false, err
	}

	sig, err := us.NewSignature(rsp)
	if err != nil {
		return false, err
	}

	valid := Verify(pk, sig, message)

	return valid, nil
}

func TestCorrectness(t *testing.T) {
	var testStrings = []struct {
		name    string
		message string
	}{
		{"plainenglish", "Hello, Alice!"},
		{"empty", ""},
		{"numeric", "0123456789"},
	}

	for _, test := range testStrings {
		t.Run(test.name, func(t *testing.T) {
			valid, err := Correctness([]byte(test.message))
			if err != nil {
				t.Fatal(err)
			}

			if !valid {
				t.Fatal(valid)
			}
		})
	}
}

func TestIncorrectness(t *testing.T) {
	src := rand.NewChaCha8([32]byte{})
	sk, _ := GenerateKey(src)
	pk := sk.Public().(*PublicKey)
	ss := sk.NewSignerState()
	cmt, _ := ss.NewCommitment()
	us := pk.NewUserState()
	chal, _ := us.NewChallenge(cmt, []byte("Hello"))
	rsp, _ := ss.NewResponse(chal)
	sig, _ := us.NewSignature(rsp)

	if valid := Verify(pk, sig, []byte("hello")); valid {
		t.Error("signatures should be case sensitive")
	}

	if valid := Verify(pk, sig, []byte("")); valid {
		t.Error("an empty string should not be valid")
	}

	if valid := Verify(pk, sig, []byte("Hello ")); valid {
		t.Error("padding should not be valid")
	}
}

func TestKeyEquality(t *testing.T) {
	key1, _ := base64.StdEncoding.DecodeString("I4rqgtrZOJl5OSmWmN6KEVKYhujsBk+PAlGXCQK8Gg0=")
	key2, _ := base64.StdEncoding.DecodeString("GyztMB0Z1Is0vPd4WjeqQQFw9GDcrljSKG/hatSygwM=")

	sk1, _ := NewPrivateKey(key1)
	sk1Copy, _ := NewPrivateKey(key1)
	sk2, _ := NewPrivateKey(key2)

	if !sk1.Equal(sk1Copy) {
		t.Error("sk1 does not equal sk1Copy")
	}

	if sk1.Equal(sk2) {
		t.Errorf("sk1 equals sk2")
	}

	t.Run("public", func(t *testing.T) {
		pk1 := sk1.Public().(*PublicKey)
		pk1Copy := sk1Copy.Public()
		pk2 := sk2.Public()

		if !pk1.Equal(pk1Copy) {
			t.Error("pk1 does not equal pk1Copy")
		}

		if pk1.Equal(pk2) {
			t.Errorf("pk1 equals pk2")
		}
	})
}

func BenchmarkKeyGen(b *testing.B) {
	src := rand.NewChaCha8([32]byte{})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sk, _ := GenerateKey(src)
		sk.Public()
	}
}

func BenchmarkBlindSchnorr(b *testing.B) {
	src := rand.NewChaCha8([32]byte{})
	sk, _ := GenerateKey(src)
	pk := sk.Public().(*PublicKey)

	b.Run("NewCommitment", func(b *testing.B) {
		ss := new(SignerState)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ss.NewCommitment()
			ss.r = nil
		}
	})

	ss := sk.NewSignerState()
	cmt, _ := ss.NewCommitment()

	b.Run("NewChallenge", func(b *testing.B) {
		us := pk.NewUserState()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			us.NewChallenge(cmt, []byte("Hello, Alice!"))
			us.cmt = nil
			us.alpha = nil
			us.beta = nil
			us.rPrime = nil
		}
	})

	b.Run("NewResponse", func(b *testing.B) {
		ss := sk.NewSignerState()
		cmt, _ := ss.NewCommitment()
		us := pk.NewUserState()
		chal, _ := us.NewChallenge(cmt, []byte("Hello, Alice!"))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			ss.NewResponse(chal)
			ss.r = nil
			ss.finished = false
		}
	})

	b.Run("NewSignature", func(b *testing.B) {
		ss := sk.NewSignerState()
		cmt, _ := ss.NewCommitment()
		us := pk.NewUserState()
		chal, _ := us.NewChallenge(cmt, []byte("Hello, Alice!"))
		rsp, _ := ss.NewResponse(chal)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := us.NewSignature(rsp)
			if err != nil {
				b.Fatal(err)
			}
			us.finished = false
		}
	})
}
