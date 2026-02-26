package waf

type Mode string

const (
	ModeBlock Mode = "block"
	ModeAudit Mode = "audit"
)
