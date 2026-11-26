package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCIIntegrations checks the files of the CI integrations against the
// command line: same flags, same version, valid JSON for Azure DevOps.
func TestCIIntegrations(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.FromSlash(p))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, p := range []string{"action.yml", "ci/gitlab/attackscout-agent.gitlab-ci.yml", "ci/azure-devops/attackscout-agent.yml",
		"ci/azure-devops/extension/tasks/AttackScoutAgentV0/index.js"} {
		s := read(p)
		for _, flag := range []string{"--fail-on", "--no-audit-link", "db", "update"} {
			if !strings.Contains(s, flag) {
				t.Errorf("%s does not use %s", p, flag)
			}
		}
		if !strings.Contains(s, "sarif") {
			t.Errorf("%s writes no SARIF report", p)
		}
	}
	if !strings.Contains(read("action.yml"), "github/codeql-action/upload-sarif") {
		t.Error("action.yml must upload the SARIF report")
	}
	for _, p := range []string{"ci/azure-devops/extension/vss-extension.json", "ci/azure-devops/extension/tasks/AttackScoutAgentV0/task.json"} {
		var v map[string]any
		if err := json.Unmarshal([]byte(read(p)), &v); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"ci/gitlab/attackscout-agent.gitlab-ci.yml", "ci/azure-devops/attackscout-agent.yml",
		"ci/azure-devops/extension/vss-extension.json", "packaging/winget/manifests/a/AttackScout/AttackscoutAgent/0.2.0/AttackScout.AttackscoutAgent.yaml"} {
		if !strings.Contains(read(p), "0.2.0") {
			t.Errorf("%s does not name version 0.2.0", p)
		}
	}
}
