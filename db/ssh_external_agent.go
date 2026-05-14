package db

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
