package blindschnorr

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	r255 "github.com/gtank/ristretto255"
)

type PublicKey struct {
	xG *r255.Element
}

func NewPublicKey(key []byte) (*PublicKey, error) {
	xG, err := r255.NewIdentityElement().SetCanonicalBytes(key)
	return &PublicKey{xG: xG}, err
}

func (pk *PublicKey) Bytes() []byte {
	if pk.xG != nil {
		return pk.xG.Bytes()
	}

	return nil
}

func (pk *PublicKey) Equal(op crypto.PublicKey) bool {
	otherPK, ok := op.(*PublicKey)
	if !ok {
		return false
	}

	return otherPK.xG.Equal(pk.xG) == 1
}

type PrivateKey struct {
	x *r255.Scalar
}

func NewPrivateKey(key []byte) (*PrivateKey, error) {
	x, err := r255.NewScalar().SetCanonicalBytes(key)
	return &PrivateKey{x: x}, err
}

func (sk *PrivateKey) Public() crypto.PublicKey {
	pk := &PublicKey{}
	pk.xG = r255.NewIdentityElement().ScalarBaseMult(sk.x)
	return pk
}

func (sk *PrivateKey) Bytes() []byte {
	if sk.x != nil {
		return sk.x.Bytes()
	}

	return nil
}

func (sk *PrivateKey) Equal(op crypto.PrivateKey) bool {
	otherSK, ok := op.(*PrivateKey)
	if !ok {
		return false
	}

	return otherSK.x.Equal(sk.x) == 1
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	randomBuffer := make([]byte, 64)

	_, err := rand.Read(randomBuffer)
	if err != nil {
		return nil, err
	}

	x, err := r255.NewScalar().SetUniformBytes(randomBuffer)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{x: x}, nil
}

type SignerState struct {
	x        *r255.Scalar
	r        *r255.Scalar
	finished bool
}

func (sk *PrivateKey) NewSignerState() *SignerState {
	return &SignerState{x: sk.x}
}

func (ss *SignerState) NewCommitment() ([]byte, error) {
	if ss.r != nil {
		return nil, errors.New("this signer state was already used to generate a commitment")
	}

	randomBuffer := make([]byte, 64)

	_, err := rand.Read(randomBuffer)
	if err != nil {
		return nil, err
	}

	r, err := r255.NewScalar().SetUniformBytes(randomBuffer)
	if err != nil {
		return nil, err
	}

	ss.r = r

	return r255.NewIdentityElement().ScalarBaseMult(r).Bytes(), nil
}

type UserState struct {
	xG       *r255.Element
	cmt      *r255.Element
	alpha    *r255.Scalar
	beta     *r255.Scalar
	rPrime   *r255.Element
	chal     *r255.Scalar
	finished bool
}

func (pk *PublicKey) NewUserState() *UserState {
	return &UserState{xG: pk.xG}
}

func (us *UserState) NewChallenge(cmt []byte, hash []byte) ([]byte, error) {
	if us.rPrime != nil {
		return nil, errors.New("user state has already been used to generate a challenge")
	}

	r, err := r255.NewIdentityElement().SetCanonicalBytes(cmt)
	if err != nil {
		return nil, err
	}

	randomBuffer := make([]byte, 128)
	_, err = rand.Read(randomBuffer)
	if err != nil {
		return nil, err
	}

	alpha, err := r255.NewScalar().SetUniformBytes(randomBuffer[:64])
	if err != nil {
		return nil, err
	}

	beta, err := r255.NewScalar().SetUniformBytes(randomBuffer[64:])
	if err != nil {
		return nil, err
	}

	alphaG := r255.NewIdentityElement().ScalarBaseMult(alpha)
	betaPK := r255.NewIdentityElement().ScalarMult(beta, us.xG)

	rPrime := r255.NewIdentityElement().Add(r, alphaG)
	rPrime.Add(rPrime, betaPK)

	cPrime, err := internalHash(rPrime, hash)
	if err != nil {
		return nil, err
	}

	chal := r255.NewScalar().Add(cPrime, beta)

	us.cmt = r
	us.alpha = alpha
	us.beta = beta
	us.rPrime = rPrime
	us.chal = chal

	return chal.Bytes(), nil
}

func (ss *SignerState) NewResponse(chalBytes []byte) ([]byte, error) {
	if ss.r == nil {
		return nil, errors.New("this signer state has not been user to generate a commitment yet")
	}

	if ss.finished {
		return nil, errors.New("this signer state has already been used to generate a response")
	}

	chal, err := r255.NewScalar().SetCanonicalBytes(chalBytes)
	if err != nil {
		return nil, err
	}

	s := r255.NewScalar().Multiply(ss.x, chal)
	s.Add(s, ss.r)

	ss.finished = true

	return s.Bytes(), nil
}

type signature struct {
	rPrime *r255.Element
	sPrime *r255.Scalar
}

func (s *signature) Bytes() []byte {
	return append(s.rPrime.Bytes(), s.sPrime.Bytes()...)
}

func (s *signature) SetCanonicalBytes(b []byte) error {
	s.rPrime = r255.NewIdentityElement()
	s.sPrime = r255.NewScalar()

	if _, err := s.rPrime.SetCanonicalBytes(b[:32]); err != nil {
		return err
	}

	_, err := s.sPrime.SetCanonicalBytes(b[32:])
	return err
}

func (us *UserState) NewSignature(rsp []byte) ([]byte, error) {
	if us.cmt == nil {
		return nil, errors.New("this user state has not yet been used to generate a challenge")
	}

	if us.finished {
		return nil, errors.New("this user state has already been used to generate a signature")
	}

	s, err := r255.NewScalar().SetCanonicalBytes(rsp)
	if err != nil {
		return nil, err
	}

	sG := r255.NewIdentityElement().ScalarBaseMult(s)

	check := r255.NewIdentityElement().ScalarMult(us.chal, us.xG)
	check.Add(check, us.cmt)

	if check.Equal(sG) == 0 {
		return nil, errors.New("signer did not honestly generate the response")
	}

	sPrime := r255.NewScalar().Add(s, us.alpha)

	us.finished = true

	sig := &signature{us.rPrime, sPrime}
	return sig.Bytes(), nil
}

func Verify(pk *PublicKey, sig []byte, message []byte) bool {
	sigDecoding := &signature{}
	if err := sigDecoding.SetCanonicalBytes(sig); err != nil {
		return false
	}

	sPrimeG := r255.NewIdentityElement().ScalarBaseMult(sigDecoding.sPrime)

	cPrime, err := internalHash(sigDecoding.rPrime, message)
	if err != nil {
		return false
	}

	cPrimeX := r255.NewIdentityElement().ScalarMult(cPrime, pk.xG)

	check := r255.NewIdentityElement().Add(sigDecoding.rPrime, cPrimeX)

	return sPrimeG.Equal(check) == 1
}

func internalHash(rp *r255.Element, m []byte) (*r255.Scalar, error) {
	h := sha512.New()
	_, err := h.Write(rp.Bytes())
	if err != nil {
		return nil, err
	}

	_, err = h.Write(m)
	if err != nil {
		return nil, err
	}

	return r255.NewScalar().FromUniformBytes(h.Sum(nil)), nil
}
