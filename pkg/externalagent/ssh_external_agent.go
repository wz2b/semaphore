package externalagent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/task_logger"
)

const (
	externalAgentProtocolVersion = "AGENT/1"

	startupTimeout  = 30 * time.Second
	shutdownTimeout = 15 * time.Second
)

type ExternalAgentRuntimeInstance struct {
	SocketPath string

	CloseFunc func() error

	cfg    db.SSHExternalAgentConfig
	logger task_logger.Logger
}

func NewSSHCertVendorExternalAgent(
	cfg db.SSHExternalAgentConfig,
	logger task_logger.Logger,
) (ExternalAgentRuntimeInstance, error) {
	instance := ExternalAgentRuntimeInstance{
		cfg:    cfg,
		logger: logger,
	}

	if err := instance.Start(); err != nil {
		return ExternalAgentRuntimeInstance{}, err
	}

	return instance, nil
}

type startupResult struct {
	socketPath string
	err        error
}

type agentResponse struct {
	id      string
	status  int
	message string
	body    []byte
}

// processState tracks child-process completion in a race-safe way.
//
// The wait goroutine writes the final cmd.Wait() result exactly once, closes
// done, and all readers fetch the cached result through errValue().
type processState struct {
	done chan struct{}

	mu  sync.RWMutex
	err error
}

func newProcessState(cmd *exec.Cmd) *processState {
	state := &processState{
		done: make(chan struct{}),
	}

	go func() {
		err := cmd.Wait()

		state.mu.Lock()
		state.err = err
		state.mu.Unlock()

		close(state.done)
	}()

	return state
}

func (s *processState) errValue() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

func (i *ExternalAgentRuntimeInstance) Start() error {
	if i.CloseFunc != nil {
		return errors.New("external SSH agent instance is already started")
	}

	i.logger.Logf(
		"external SSH agent config before validation: command=%q args=%v config_len=%d",
		i.cfg.Command,
		i.cfg.Args,
		len(i.cfg.Config),
	)

	commandPath, err := validateCommand(i.cfg.Command)
	if err != nil {
		return err
	}

	shutdownCh := make(chan struct{})
	stoppedCh := make(chan struct{})
	readyCh := make(chan startupResult, 1)

	var (
		closeOnce sync.Once
		closeErr  error
		closeMu   sync.Mutex
	)

	// This CloseFunc intentionally overrides the default Agent.Close behavior in
	// pkg/ssh/agent.go. The external process owns the agent socket lifecycle, so
	// shutdown must flow through the external protocol and process cleanup path.
	i.CloseFunc = func() error {
		closeOnce.Do(func() {
			close(shutdownCh)
		})

		<-stoppedCh

		closeMu.Lock()
		defer closeMu.Unlock()
		return closeErr
	}

	go func() {
		err := runExternalAgentLifecycle(commandPath, i.cfg, i.logger, shutdownCh, readyCh)

		closeMu.Lock()
		closeErr = err
		closeMu.Unlock()

		close(stoppedCh)
	}()

	select {
	case ready := <-readyCh:
		if ready.err != nil {
			_ = i.CloseFunc()
			return ready.err
		}

		i.SocketPath = ready.socketPath
		return nil
	case <-time.After(startupTimeout):
		_ = i.CloseFunc()
		return fmt.Errorf("timed out waiting for external SSH agent startup after %s", startupTimeout)
	}
}

func runExternalAgentLifecycle(
	commandPath string,
	cfg db.SSHExternalAgentConfig,
	logger task_logger.Logger,
	shutdownCh <-chan struct{},
	readyCh chan<- startupResult,
) error {
	logger.Logf("starting external SSH agent: command=%s args=%v", commandPath, cfg.Args)
	cmd := exec.Command(commandPath, cfg.Args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		readyCh <- startupResult{err: fmt.Errorf("open stdin for external SSH agent: %w", err)}
		return fmt.Errorf("open stdin for external SSH agent: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		readyCh <- startupResult{err: fmt.Errorf("open stdout for external SSH agent: %w", err)}
		return fmt.Errorf("open stdout for external SSH agent: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		readyCh <- startupResult{err: fmt.Errorf("open stderr for external SSH agent: %w", err)}
		return fmt.Errorf("open stderr for external SSH agent: %w", err)
	}

	if err = cmd.Start(); err != nil {
		readyCh <- startupResult{err: fmt.Errorf("start external SSH agent command %q: %w", commandPath, err)}
		return fmt.Errorf("start external SSH agent command %q: %w", commandPath, err)
	}

	logger.Logf("external SSH agent started: command=%s pid=%d", commandPath, cmd.Process.Pid)

	// stderrDone is only used to let the stderr logging goroutine drain and exit
	// cleanly before this lifecycle goroutine returns. It is not the process
	// liveness signal; process.done is the real one.
	//
	// In normal operation the child process keeps stderr open until it exits, EOF is
	// observed by streamStderr(), and stderrDone closes naturally. If an unusual
	// external agent explicitly closes stderr but keeps running, stderrDone may close
	// early. That is OK: we will simply stop receiving stderr logs, while process
	// liveness is still tracked by cmd.Wait() via process.done.
	stderrDone := streamStderr(logger, stderr)

	stdoutReader := bufio.NewReader(stdout)

	process := newProcessState(cmd)

	// Start handshake: send opaque config and wait for socket path response.
	if err = writeRequest(stdin, 1, "config", []byte(cfg.Config)); err != nil {
		terminateErr := terminateProcess(cmd, process)
		<-stderrDone

		wrapped := fmt.Errorf("send config request to external SSH agent: %w", err)
		readyCh <- startupResult{err: wrapped}
		if terminateErr != nil {
			return errors.Join(wrapped, terminateErr)
		}
		return wrapped
	}

	configResponse, err := readResponseWithTimeout(stdoutReader, process, startupTimeout)
	if err != nil {
		terminateErr := terminateProcess(cmd, process)
		<-stderrDone

		wrapped := fmt.Errorf("read config response from external SSH agent: %w", err)
		readyCh <- startupResult{err: wrapped}
		if terminateErr != nil {
			return errors.Join(wrapped, terminateErr)
		}
		return wrapped
	}

	if configResponse.id != "1" {
		terminateErr := terminateProcess(cmd, process)
		<-stderrDone

		err = fmt.Errorf("external SSH agent returned mismatched response id for config request: got %q", configResponse.id)
		readyCh <- startupResult{err: err}
		if terminateErr != nil {
			return errors.Join(err, terminateErr)
		}
		return err
	}

	if configResponse.status != 200 {
		terminateErr := terminateProcess(cmd, process)
		<-stderrDone

		err = fmt.Errorf(
			"external SSH agent rejected config request: status=%d message=%q body=%q",
			configResponse.status,
			configResponse.message,
			strings.TrimSpace(string(configResponse.body)),
		)
		readyCh <- startupResult{err: err}
		if terminateErr != nil {
			return errors.Join(err, terminateErr)
		}
		return err
	}

	socketPath := strings.TrimSpace(string(configResponse.body))
	if socketPath == "" {
		terminateErr := terminateProcess(cmd, process)
		<-stderrDone

		err = errors.New("external SSH agent returned empty socket path")
		readyCh <- startupResult{err: err}
		if terminateErr != nil {
			return errors.Join(err, terminateErr)
		}
		return err
	}

	logger.Logf("external SSH agent reported socket path: %s", socketPath)
	readyCh <- startupResult{socketPath: socketPath}

	// The process stays alive for task duration. CloseFunc triggers this shutdown
	// path via shutdownCh and waits for this goroutine to complete.
	select {
	case <-shutdownCh:
		logger.Log("external SSH agent shutdown requested")
	case <-process.done:
		<-stderrDone
		processErr := process.errValue()
		if processErr == nil {
			return errors.New("external SSH agent exited unexpectedly before shutdown request")
		}
		return fmt.Errorf("external SSH agent exited unexpectedly before shutdown request: %w", processErr)
	}

	shutdownErr := writeRequest(stdin, 2, "shutdown", nil)
	if shutdownErr == nil {
		var shutdownResponse agentResponse
		shutdownResponse, shutdownErr = readResponseWithTimeout(stdoutReader, process, shutdownTimeout)
		if shutdownErr == nil {
			if shutdownResponse.id != "2" {
				shutdownErr = fmt.Errorf("external SSH agent returned mismatched response id for shutdown request: got %q", shutdownResponse.id)
			} else if shutdownResponse.status != 200 {
				shutdownErr = fmt.Errorf(
					"external SSH agent rejected shutdown request: status=%d message=%q body=%q",
					shutdownResponse.status,
					shutdownResponse.message,
					strings.TrimSpace(string(shutdownResponse.body)),
				)
			}
		}
	}

	waitErr := waitForProcessExit(process, shutdownTimeout)
	if waitErr != nil {
		killErr := terminateProcess(cmd, process)
		waitErr = errors.Join(waitErr, killErr)
	}

	<-stderrDone

	if shutdownErr != nil || waitErr != nil {
		return errors.Join(shutdownErr, waitErr)
	}

	logger.Log("external SSH agent stopped")
	return nil
}

func validateCommand(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", errors.New("external SSH agent command is required")
	}

	commandPath, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Errorf("external SSH agent command %q not found: %w", command, err)
	}

	return commandPath, nil
}

func writeRequest(w io.Writer, id int, method string, body []byte) error {
	if body == nil {
		body = []byte{}
	}

	if _, err := fmt.Fprintf(w,
		"%s REQUEST\nId: %d\nMethod: %s\nContent-Length: %d\n\n",
		externalAgentProtocolVersion,
		id,
		method,
		len(body),
	); err != nil {
		return err
	}

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}

	return nil
}

func readResponseWithTimeout(
	r *bufio.Reader,
	process *processState,
	timeout time.Duration,
) (agentResponse, error) {
	resultCh := make(chan struct {
		response agentResponse
		err      error
	}, 1)

	go func() {
		response, err := readResponse(r)
		resultCh <- struct {
			response agentResponse
			err      error
		}{
			response: response,
			err:      err,
		}
	}()

	select {
	case <-process.done:
		if process.errValue() == nil {
			return agentResponse{}, errors.New("external SSH agent process exited unexpectedly")
		}
		return agentResponse{}, fmt.Errorf("external SSH agent process exited: %w", process.errValue())
	case result := <-resultCh:
		if result.err != nil {
			return agentResponse{}, result.err
		}
		return result.response, nil
	case <-time.After(timeout):
		return agentResponse{}, fmt.Errorf("timed out waiting for external SSH agent response after %s", timeout)
	}
}

func readResponse(r *bufio.Reader) (agentResponse, error) {
	startLine, headers, body, err := readMessage(r)
	if err != nil {
		return agentResponse{}, err
	}

	if startLine != externalAgentProtocolVersion+" RESPONSE" {
		return agentResponse{}, fmt.Errorf("invalid response start line %q", startLine)
	}

	id := headers["Id"]
	if id == "" {
		return agentResponse{}, errors.New("response missing Id header")
	}

	statusRaw := headers["Status"]
	if statusRaw == "" {
		return agentResponse{}, errors.New("response missing Status header")
	}

	status, err := strconv.Atoi(statusRaw)
	if err != nil {
		return agentResponse{}, fmt.Errorf("invalid response Status header %q: %w", statusRaw, err)
	}

	return agentResponse{
		id:      id,
		status:  status,
		message: headers["Message"],
		body:    body,
	}, nil
}

func readMessage(r *bufio.Reader) (string, map[string]string, []byte, error) {
	startLine, err := readLine(r)
	if err != nil {
		return "", nil, nil, err
	}

	headers := make(map[string]string)
	for {
		line, lineErr := readLine(r)
		if lineErr != nil {
			return "", nil, nil, lineErr
		}

		if line == "" {
			break
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return "", nil, nil, fmt.Errorf("malformed header line %q", line)
		}

		headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}

	contentLengthRaw := headers["Content-Length"]
	if contentLengthRaw == "" {
		return "", nil, nil, errors.New("missing Content-Length header")
	}

	contentLength, err := strconv.Atoi(contentLengthRaw)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid Content-Length header %q: %w", contentLengthRaw, err)
	}

	if contentLength < 0 {
		return "", nil, nil, fmt.Errorf("invalid negative Content-Length %d", contentLength)
	}

	body := make([]byte, contentLength)
	if contentLength > 0 {
		if _, err = io.ReadFull(r, body); err != nil {
			return "", nil, nil, fmt.Errorf("read response body: %w", err)
		}
	}

	return startLine, headers, body, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}

func waitForProcessExit(process *processState, timeout time.Duration) error {
	select {
	case <-process.done:
		return process.errValue()
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for external SSH agent process exit after %s", timeout)
	}
}

func terminateProcess(cmd *exec.Cmd, process *processState) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	select {
	case <-process.done:
		return nil
	default:
	}

	if err := cmd.Process.Kill(); err != nil {
		return fmt.Errorf("kill external SSH agent process: %w", err)
	}

	select {
	case <-process.done:
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("timed out waiting for external SSH agent process to exit after kill (%s)", shutdownTimeout)
	}
}

func streamStderr(logger task_logger.Logger, stderr io.Reader) <-chan struct{} {
	done := make(chan struct{})

	go func() {
		defer close(done)

		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			logger.Logf("external SSH agent stderr: %s", line)
		}

		if err := scanner.Err(); err != nil {
			logger.Logf("external SSH agent stderr stream error: %v", err)
		}
	}()

	return done
}
