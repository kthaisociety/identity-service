// Package safelog configures process logs without emitting error objects that
// could contain credentials or personal data.
package safelog

import (
	"io"
	"log/slog"
)

// New keeps the fixed message and a small set of safe, structured fields.
// In particular, ZITADEL's oidc_error and error attributes are discarded.
func New(w io.Writer) *slog.Logger {
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) != 0 {
				return slog.Attr{}
			}
			switch attr.Key {
			case slog.TimeKey, slog.LevelKey, slog.MessageKey,
				"category", "listener", "route", "status":
				return attr
			default:
				return slog.Attr{}
			}
		},
	})
	return slog.New(handler)
}
