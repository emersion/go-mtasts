package mtasts

import (
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const testPolicyString = `{
	"version": "STSv1",
	"mode": "enforce",
	"mx": ["*.mail.example.com"],
	"max_age": 123456
}`

var testPolicy = &Policy{
	Version: "STSv1",
	Mode: ModeEnforce,
	MaxAge: 123456,
	MX: []string{"*.mail.example.com"},
}

type testHTTPTransport struct{}

func (t *testHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Body: ioutil.NopCloser(strings.NewReader(testPolicyString)),
	}, nil
}

func init() {
	lookupTXT = func(host string) ([]string, error) {
		return []string{"v=STSv1; id=20160831085700Z;"}, nil
	}

	httpClient.Transport = new(testHTTPTransport)
}

func TestFetch(t *testing.T) {
	policy, err := Fetch("example.com")
	if err != nil {
		t.Fatal("Expected no error while fetching policy, got:", err)
	}

	if !reflect.DeepEqual(policy, testPolicy) {
		t.Errorf("Invalid policy: expected \n%+v\n but got \n%+v", testPolicy, policy)
	}
}
