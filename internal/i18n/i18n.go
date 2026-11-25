// Package i18n renders report messages in English (default) or French.
package i18n

import (
	"encoding/json"
	"fmt"
)

// Langs lists the supported languages.
var Langs = []string{"en", "fr"}

// Msg is a message key and its arguments, rendered late in the chosen language.
type Msg struct {
	Key  string
	Args []any
}

// M builds a message.
func M(key string, args ...any) Msg { return Msg{Key: key, Args: args} }

// IsZero tells whether the message is empty.
func (m Msg) IsZero() bool { return m.Key == "" }

// Render returns the message in lang ("en" or "fr"); unknown keys are shown as is.
func (m Msg) Render(lang string) string {
	if m.Key == "" {
		return ""
	}
	t, ok := catalog[m.Key]
	if !ok {
		return m.Key
	}
	f := t[0]
	if lang == "fr" {
		f = t[1]
	}
	if len(m.Args) == 0 {
		return f
	}
	args := make([]any, len(m.Args))
	for i, a := range m.Args {
		if sub, ok := a.(Msg); ok {
			a = sub.Render(lang)
		}
		args[i] = a
	}
	return fmt.Sprintf(f, args...)
}

// MarshalJSON renders the English text, for debugging only: reports render
// messages through Render.
func (m Msg) MarshalJSON() ([]byte, error) { return json.Marshal(m.Render("en")) }

// Has tells whether a key exists in the catalog.
func Has(key string) bool {
	t, ok := catalog[key]
	return ok && t[0] != "" && t[1] != ""
}

// Valid tells whether lang is supported.
func Valid(lang string) bool { return lang == "en" || lang == "fr" }
