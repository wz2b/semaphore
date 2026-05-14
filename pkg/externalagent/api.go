package externalagent

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ExternalAgentRequest is sent from SemaphoreUI to the external agent.
//
// In the AGENT/1 protocol, requests are written to the agent process's
// standard input. Version 1 defines two methods:
//
//   - config
//   - shutdown
//
// The Body is an opaque byte sequence whose meaning depends on the method.
// For config requests, Body contains the provider-specific configuration blob.
// For shutdown requests, Body is normally empty.
type ExternalAgentRequest struct {
	Method string
	Body   []byte
}

// ExternalAgentResponse is sent from the external agent back to SemaphoreUI.
//
// In the AGENT/1 protocol, responses are written by the agent process to
// standard output. A Status value of 200 means success. Any other status value
// is treated as failure by SemaphoreUI.
//
// For a successful config response, Body contains the SSH_AUTH_SOCK path.
// For an error response, Body contains a user-readable explanation.
// For a successful shutdown response, Body is normally empty.
type ExternalAgentResponse struct {
	Status int
	Body   []byte
}

func SendExternalAgentRequest(
	stdin io.Writer,
	stdout io.Reader,
	req *ExternalAgentRequest,
) (*ExternalAgentResponse, error) {
	if err := writeExternalAgentRequest(stdin, req); err != nil {
		return nil, err
	}

	return readExternalAgentResponse(stdout)
}
func writeExternalAgentRequest(w io.Writer, req *ExternalAgentRequest) error {
	if req == nil {
		return fmt.Errorf("external agent request is nil")
	}
	if req.Method == "" {
		return fmt.Errorf("external agent request method is required")
	}

	_, err := fmt.Fprintf(
		w,
		"AGENT/1 REQUEST\nMethod: %s\nContent-Length: %d\n\n",
		req.Method,
		len(req.Body),
	)
	if err != nil {
		return fmt.Errorf("write external agent request header: %w", err)
	}

	if len(req.Body) > 0 {
		if _, err := w.Write(req.Body); err != nil {
			return fmt.Errorf("write external agent request body: %w", err)
		}
	}

	return nil
}

func readExternalAgentResponse(r io.Reader) (*ExternalAgentResponse, error) {
	br := bufio.NewReader(r)

	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read external agent response status line: %w", err)
	}

	if strings.TrimSpace(line) != "AGENT/1 RESPONSE" {
		return nil, fmt.Errorf("invalid external agent response status line: %q", strings.TrimSpace(line))
	}

	var status int
	var contentLength int
	contentLengthSeen := false

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read external agent response header: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid external agent response header: %q", line)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch strings.ToLower(key) {
		case "status":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid external agent response status %q: %w", value, err)
			}
			status = parsed

		case "content-length":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid external agent response content length %q: %w", value, err)
			}
			if parsed < 0 {
				return nil, fmt.Errorf("invalid external agent response content length %d", parsed)
			}
			contentLength = parsed
			contentLengthSeen = true

		default:
			// Version 1 ignores unknown response headers.
		}
	}

	if status == 0 {
		return nil, fmt.Errorf("external agent response status is required")
	}
	if !contentLengthSeen {
		return nil, fmt.Errorf("external agent response content length is required")
	}

	body := make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, fmt.Errorf("read external agent response body: %w", err)
		}
	}

	return &ExternalAgentResponse{
		Status: status,
		Body:   body,
	}, nil
}
