package resolver

import "testing"

func TestCleanNameV5(t *testing.T) {
	cases := []struct {
		key             string
		expectedName    string
		expectedVersion string
	}{
		{"/lodash/4.17.21", "lodash", "4.17.21"},
		{"/@babel/core/7.0.0", "@babel/core", "7.0.0"},
		{"/foo/1.0.0_react@17.0.0", "foo", "1.0.0"},
		{"/@scope/pkg/1.0.0_react@17.0.0", "@scope/pkg", "1.0.0"},
		{"/bar/2.0.0_eslint@7.0.0+typescript@4.0.0", "bar", "2.0.0"},
	}
	for _, c := range cases {
		name, version := cleanNameV5(c.key)
		if name != c.expectedName || version != c.expectedVersion {
			t.Errorf("cleanNameV5(%q) = (%q, %q); want (%q, %q)",
				c.key, name, version, c.expectedName, c.expectedVersion)
		}
	}
}

func TestCleanNameV6(t *testing.T) {
	cases := []struct {
		key             string
		expectedName    string
		expectedVersion string
	}{
		{"/lodash@4.17.21", "lodash", "4.17.21"},
		{"/@babel/core@7.0.0", "@babel/core", "7.0.0"},
		{"/ajv-keywords@3.4.1(ajv@6.10.2)", "ajv-keywords", "3.4.1"},
		{"/@scope/pkg@1.0.0(react@17.0.0)(typescript@5.0.0)", "@scope/pkg", "1.0.0"},
	}
	for _, c := range cases {
		name, version := cleanNameV6(c.key)
		if name != c.expectedName || version != c.expectedVersion {
			t.Errorf("cleanNameV6(%q) = (%q, %q); want (%q, %q)",
				c.key, name, version, c.expectedName, c.expectedVersion)
		}
	}
}

func TestStripPeerSuffix(t *testing.T) {
	if got := stripPeerSuffixV5("2.0.0_react@17.0.0"); got != "2.0.0" {
		t.Errorf("stripPeerSuffixV5 = %q; want 2.0.0", got)
	}
	if got := stripPeerSuffixV6("3.4.1(ajv@6.10.2)"); got != "3.4.1" {
		t.Errorf("stripPeerSuffixV6 = %q; want 3.4.1", got)
	}
}
