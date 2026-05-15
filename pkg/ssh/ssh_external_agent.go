package ssh

import (
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/externalagent"
	"github.com/semaphoreui/semaphore/pkg/task_logger"
)

func installSSHCertExternal(
	cfg db.SSHExternalAgentConfig,
	logger task_logger.Logger,
) (installation AccessKeyInstallation, err error) {

	result, err := externalagent.NewSSHCertVendorExternalAgent(cfg, logger)
	if err != nil {
		return installation, err
	}

	agent := Agent{
		SocketFile: result.SocketPath,
		closeFunc:  result.CloseFunc,
	}

	installation.SSHAgent = &agent

	return installation, nil
}
