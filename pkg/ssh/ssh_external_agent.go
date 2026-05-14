package ssh

import (
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/task_logger"
)

func installSSHCertExternal(
	cfg db.SSHExternalAgentConfig,
	logger task_logger.Logger,
) (installation AccessKeyInstallation, err error) {

	agent, err := NewSSHCertVendorExternalAgent(cfg, logger)
	if err != nil {
		return installation, err
	}

	installation.SSHAgent = &agent

	installation.Login = cfg.Config

	return installation, nil
}

func NewSSHCertVendorExternalAgent(
	cfg db.SSHExternalAgentConfig,
	logger task_logger.Logger,
) (Agent, error) {
	// generate keypair
	// vend cert
	// start normal ssh-agent
	// ssh-add key
	// return normal Agent
	return Agent{}, nil
}
