// Package sweetcookie loads cookies from local browser profiles (Chrome-family, Firefox, Safari).
//
// This is intended for local tooling (CLI helpers, dev scripts, test harnesses). It reads local
// browser state, may trigger keychain/keyring prompts, and should not be used in server contexts.
package sweetcookie
