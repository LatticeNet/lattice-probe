package harness

import (
	"encoding/json"
	"fmt"
	"os"
)

// Params holds the throwaway credentials shared by the server config and
// both probes. cmd/aux setup generates them; nothing here is a real secret.
type Params struct {
	Host           string         `json:"host"`
	Ports          map[string]int `json:"ports"`
	SSKey          string         `json:"ss_key"`
	SSKeyWrong     string         `json:"ss_key_wrong"`
	UUID           string         `json:"uuid"`
	UUIDWrong      string         `json:"uuid_wrong"`
	Password       string         `json:"password"`
	PasswordWrong  string         `json:"password_wrong"`
	RealityPriv    string         `json:"reality_private_key"`
	RealityPub     string         `json:"reality_public_key"`
	ShortID        string         `json:"short_id"`
	ShortIDWrong   string         `json:"short_id_wrong"`
	RealitySNI     string         `json:"reality_sni"`
	RealityPubSNI  string         `json:"reality_public_sni"`
	TLSSNI         string         `json:"tls_sni"`
	WSPath         string         `json:"ws_path"`
	TargetURL      string         `json:"target_url"`
	TargetAddr     string         `json:"target_addr"`
	RealityDest    string         `json:"reality_dest"`
	RealityPubDest string         `json:"reality_public_dest"`
}

// Protocols in the order every suite runs them.
var Protos = []string{"ss", "vmess_ws", "vless_reality", "trojan_tls", "hysteria2", "tuic"}

type Case struct {
	Proto   string `json:"proto"`
	Variant string `json:"variant"`
}

// Resolved is a case with every credential substituted, so engines only
// translate field names and never decide which value is wrong.
type Resolved struct {
	Proto     string
	Server    string
	Port      int
	SSKey     string
	UUID      string
	Password  string
	ShortID   string
	PublicKey string
	SNI       string
	WSPath    string
}

func LoadParams(path string) (*Params, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Params
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Params) Resolve(c Case) (Resolved, error) {
	r := Resolved{
		Proto:     c.Proto,
		Server:    p.Host,
		Port:      p.Ports[c.Proto],
		SSKey:     p.SSKey,
		UUID:      p.UUID,
		Password:  p.Password,
		ShortID:   p.ShortID,
		PublicKey: p.RealityPub,
		SNI:       p.TLSSNI,
		WSPath:    p.WSPath,
	}
	if c.Proto == "vless_reality" {
		r.SNI = p.RealitySNI
	}
	switch c.Variant {
	case "valid":
	case "wrong_password":
		r.SSKey = p.SSKeyWrong
		r.Password = p.PasswordWrong
	case "wrong_uuid":
		r.UUID = p.UUIDWrong
	case "wrong_short_id":
		r.ShortID = p.ShortIDWrong
	case "public_valid":
		r.Port = p.Ports["vless_reality_public"]
		r.SNI = p.RealityPubSNI
	case "public_wrong_short_id":
		r.Port = p.Ports["vless_reality_public"]
		r.SNI = p.RealityPubSNI
		r.ShortID = p.ShortIDWrong
	default:
		return r, fmt.Errorf("unknown variant %q", c.Variant)
	}
	return r, nil
}

// ErrorCases are the correctness probes: one wrong credential at a time.
var ErrorCases = []Case{
	{"ss", "wrong_password"},
	{"vmess_ws", "wrong_uuid"},
	{"vless_reality", "wrong_uuid"},
	{"vless_reality", "wrong_short_id"},
	{"vless_reality", "public_wrong_short_id"},
	{"trojan_tls", "wrong_password"},
	{"hysteria2", "wrong_password"},
	{"tuic", "wrong_password"},
	{"tuic", "wrong_uuid"},
}
