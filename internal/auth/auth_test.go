package auth

import (
	"testing"
)

type passwordHashTestCase struct {
	input       string // the password you want to hash
	shouldMatch bool   // whether CheckPasswordHash should succeed
	expectError bool   // whether you expect hashing to error
}

func TestPasswordHash(t *testing.T) {
	cases := []passwordHashTestCase{
		{input: "password1234", shouldMatch: true, expectError: false},
		{input: "", shouldMatch: false, expectError: true}, // edge case for empty password
	}
	for _, c := range cases {
		hash, err := HashPassword(c.input)

		// Check hashing error behavior
		if c.expectError && err == nil {
			t.Fatalf("expected an error for input: %v, got none", c.input)
		}
		if !c.expectError && err != nil {
			t.Fatalf("did not expect an error for input: %v, got: %v", c.input, err)
		}

		// Only check hash validity if there's no error
		if !c.expectError {
			err = CheckPasswordHash(c.input, hash)
			if c.shouldMatch && err != nil {
				t.Fatalf("expected matching hash for input: %v, got error: %v", c.input, err)
			}
			if !c.shouldMatch && err == nil {
				t.Fatalf("did not expect matching hash for input: %v, but no error was returned", c.input)
			}
		}
	}
}
