// Package mtasts handles SMTP MTA Strict Transport Security.
package mtasts

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// A PolicyMode describes the expected behavior of a sending MTA in the case of
// a policy validation failure.
type PolicyMode string

const (
	// Sending MTAs treat STS policy failures as a mail delivery error, and MUST
	// NOT deliver the message to this host.
	ModeEnforce PolicyMode = "enforce"
	// Sending MTAs merely send a report indicating policy application failures.
	ModeReport = "report"
)

// A Policy is a committment by the Policy Domain to support PKIX authenticated
// TLS for the specified MX hosts.
type Policy struct {
	Version string `json:"version"`
	// The expected behavior of a sending MTA in the case of a policy validation
	// failure.
	Mode PolicyMode `json:"mode"`
	// Max lifetime of the policy, in seconds.
	MaxAge time.Duration `json:"max_age"`
	// One or more patterns matching the expected MX for this domain.
	MX []string `json:"mx"`
}

var lookupTXT = net.LookupTXT

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("mtasts: HTTP redirects are forbidden")
	},
	Timeout: time.Minute,
}

// Fetch retrieves the MTA STS policy for a domain. It returns a nil policy if
// no policy is available.
func Fetch(domain string) (*Policy, error) {
	policyHost := "mta-sts."+domain

	txts, err := lookupTXT(policyHost)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=STSv1;") {
			records = append(records, txt)
		}
	}
	if len(records) != 1 {
		return nil, nil
	}

	// TODO: parse record
	/*fields, err := parseRecord(records[0])
	if err != nil {
		return nil, err
	}*/

	resp, err := httpClient.Get("https://"+policyHost+"/.well-known/mta-sts.json")
	if err != nil {
		return nil, err
	}

	policy := new(Policy)
	if err := json.NewDecoder(resp.Body).Decode(policy); err != nil {
		return nil, err
	}
	policy.MaxAge *= time.Second

	if policy.Version != "STSv1" {
		return policy, errors.New("mtasts: unsupported policy version")
	}
	return policy, nil
}
