package externalagent

import (
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/task_logger"
)

type ExternalAgentRuntimeInstance struct {
	SocketPath string

	CloseFunc func() error
}

func NewSSHCertVendorExternalAgent(
	cfg db.SSHExternalAgentConfig,
	logger task_logger.Logger,
) (ExternalAgentRuntimeInstance, error) {
	// TODO:
	// - start external agent command
	// - send config
	// - receive socket path
	// - return socket path and cleanup function

	instance := ExternalAgentRuntimeInstance{
		SocketPath: "",
		CloseFunc: func() error {
			// TODO: shut down external agent process
			return nil
		},
	}

	return instance, nil
}
