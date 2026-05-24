package db

import (
	"encoding/json"
	"fmt"
	"unicode"
)

const (
	ExternalSshAgent AccessKeyType = "ssh_agent_external"
)

//
// This structure describes what is stored in the SemaphoreUI access key.
//
// The 'command' field identifies the external agent executable. It must be a
// literal executable path. Runtime substitutions are not allowed in 'command'.
//
// The 'args' field supports a limited set of runtime substitutions. These values
// come from SemaphoreUI's task execution context and may be useful for logging,
// traceability, runtime file placement, and external agent policy decisions.
//
// Agents may use these values as part of their authorization model if they trust
// the SemaphoreUI instance and the local process boundary. They should not treat
// these values as independent cryptographic proof of identity. For example,
// '{{ .UserID }}' identifies the SemaphoreUI user associated with the task run,
// but it is still an assertion provided by SemaphoreUI.
//
// Provider-specific secret configuration belongs in 'config'. SemaphoreUI treats
// 'config' as opaque and passes it to the agent over the control protocol without
// parsing, transforming, or injecting runtime values into it.
//
// Example:
//
// {
//   "command": "/usr/local/bin/ssh-cert-agent",
//   "args": [
//     "--runtime-dir", "{{ .RuntimeDir }}",
//     "--task-id", "{{ .TaskID }}",
//     "--project-id", "{{ .ProjectID }}",
//     "--template-id", "{{ .TemplateID }}",
//     "--user-id", "{{ .UserID }}"
//   ],
//   "config": {
//     "trust_domain": "lab",
//     "default_principal": "ansible",
//     "max_ttl_seconds": 1800,
//     "signing_service_url": "https://ssh-ca.example.edu"
//   }
// }
//

type SSHExternalAgentConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`

	// Config is an opaque provider-specific configuration blob.
	// Semaphore stores it and passes it to the external agent, but does not parse it.
	Config string `json:"config"`
}

func (c *SSHExternalAgentConfig) UnmarshalJSON(data []byte) error {
	type rawSSHExternalAgentConfig struct {
		Command string          `json:"command"`
		Args    json.RawMessage `json:"args"`
		Config  string          `json:"config"`
	}

	var raw rawSSHExternalAgentConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	c.Command = raw.Command
	c.Config = raw.Config
	c.Args = []string{}

	if len(raw.Args) == 0 || string(raw.Args) == "null" {
		return nil
	}

	var argsList []string
	if err := json.Unmarshal(raw.Args, &argsList); err == nil {
		c.Args = argsList
		return nil
	}

	var argsString string
	if err := json.Unmarshal(raw.Args, &argsString); err != nil {
		return fmt.Errorf("invalid ssh external agent args: expected string or array of strings")
	}

	parsedArgs, err := parseExternalAgentArgs(argsString)
	if err != nil {
		return fmt.Errorf("invalid ssh external agent args: %w", err)
	}

	c.Args = parsedArgs
	return nil
}

func parseExternalAgentArgs(s string) ([]string, error) {
	args := make([]string, 0)
	current := make([]rune, 0)

	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	flushCurrent := func() {
		if len(current) == 0 {
			return
		}
		args = append(args, string(current))
		current = current[:0]
	}

	for _, r := range s {
		if escaped {
			current = append(current, r)
			escaped = false
			continue
		}

		if inSingleQuote {
			if r == '\'' {
				inSingleQuote = false
			} else {
				current = append(current, r)
			}
			continue
		}

		if inDoubleQuote {
			switch r {
			case '\\':
				escaped = true
			case '"':
				inDoubleQuote = false
			default:
				current = append(current, r)
			}
			continue
		}

		switch {
		case unicode.IsSpace(r):
			flushCurrent()
		case r == '\\':
			escaped = true
		case r == '\'':
			inSingleQuote = true
		case r == '"':
			inDoubleQuote = true
		default:
			current = append(current, r)
		}
	}

	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}

	if inSingleQuote || inDoubleQuote {
		return nil, fmt.Errorf("unterminated quote")
	}

	flushCurrent()

	if len(args) == 0 {
		return []string{}, nil
	}

	return args, nil
}

// SemaphoreUI interprets the external agent `command` and `args` fields. The `command` field identifies the
// executable to start. The `args` field provides command-line arguments passed directly to the executable without
// using a shell.
//
// The provider-specific `config` field is opaque and is passed to the agent as the body of the `config` control request.
//
// SemaphoreUI may support a small set of substitutions in `args` so that task-specific values can be passed to the agent.
// Substitution should be limited to explicitly supported fields such as task ID, project ID, template ID, inventory ID,
// user ID, and runtime directory.
//
// Substitution should not be applied to the `command` field. The executable path should be literal.
//
// SemaphoreUI should execute the command directly rather than through a shell.

type ExternalAgentTemplateContext struct {
	TaskID      string
	ProjectID   string
	TemplateID  string
	InventoryID string
	UserID      string
	RuntimeDir  string
}
