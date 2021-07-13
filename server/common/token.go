package common

import (
	"time"
)

const (
	AdminClaim = "ADMIN"
)

type AdminToken struct {
	Claim  string    `json:"token"`
	Expire time.Time `json:"time"`
}

func NewAdminToken() AdminToken {
	return AdminToken{
		Claim:  AdminClaim,
		Expire: time.Now().Add(time.Hour * 24),
	}
}

func (t AdminToken) IsAdmin() bool { return t.Claim == AdminClaim }
func (t AdminToken) IsValid() bool { return t.Expire.Sub(time.Now()) > 0 }
