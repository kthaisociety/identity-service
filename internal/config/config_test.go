package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateNamesEveryMissingVariable(t *testing.T) {
	err := (&Config{PublicPort: "8000", InternalPort: "8001"}).Validate()

	assert.EqualError(t, err, "missing required environment variables: DATABASE_URL, IDENTITY_SERVICE_SECRET")
}

func TestValidateRejectsTheSamePortTwice(t *testing.T) {
	c := &Config{DatabaseURL: "postgres://x", ServiceSecret: "s", PublicPort: "8000", InternalPort: "8000"}

	assert.Error(t, c.Validate())
}
