# Changelog

## Unreleased

- Implemented external SSH agent runtime lifecycle in `pkg/externalagent/ssh_external_agent.go`, including command validation, AGENT/1 `config`/`shutdown` stdio protocol handling, socket path extraction, and idempotent process shutdown/cleanup through `CloseFunc`.

