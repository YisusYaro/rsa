package user

import (
	"crypto/rsa"
)

type User struct {
	Name              string
	EncryptedPassword string
	PlainPassword     string
	PrivateKey        *rsa.PrivateKey
	PublicKey         *rsa.PublicKey
}
