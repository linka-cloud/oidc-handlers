package oidc_handlers

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

var (
	nouns = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func newState() string {
	var state string
	for i := 0; i < 32; i++ {
		state += string(nouns[rand.Int() % len(nouns)])
	}
	return state
}
