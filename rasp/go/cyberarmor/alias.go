package cyberarmor

import (
	"net/http"

	legacy "github.com/cyberarmor/rasp-go"
)

type Config = legacy.Config
type Inspector = legacy.Inspector
type InspectionResult = legacy.InspectionResult

func DefaultConfig() Config {
	return legacy.DefaultConfig()
}

func New(cfg Config) *Inspector {
	return legacy.New(cfg)
}

func Middleware(ins *Inspector, next http.Handler) http.Handler {
	return ins.HTTPMiddleware(next)
}
