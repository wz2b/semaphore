# External SSH Agent Concept for SemaphoreUI

## Purpose

This document describes a pattern for using a custom external SSH agent with SemaphoreUI.

The primary goal is to let SemaphoreUI delegate SSH credential handling to an external process instead of requiring every
task run to use SemaphoreUI's built-in SSH key handling. This is especially useful for automation systems such as
Ansible, where a job may need temporary access to one or more servers, but where permanently storing broadly useful SSH
keys creates avoidable risk.

One important use case is SSH certificate-based authentication. In that model, an external agent can generate or obtain
short-lived SSH certificates instead of relying only on long-lived static SSH private keys.

However, the external agent model is not limited to SSH certificates. It can also support ordinary SSH keys,
hardware-backed keys, dynamically selected key sets, Vault-backed credentials, cloud signing services, or other
credential sources.

A secondary goal is to make SSH credential selection more flexible and policy-driven. For example, an external agent
could expose different identities based on the SemaphoreUI project, task template, requesting user, target inventory,
trust domain, environment, or approval state.

This allows the system to move away from a simple model of:

> This task has this one SSH key.

and toward a more flexible model of:

> This task is allowed to use these SSH identities, for this purpose, right now.

## Scope

This design is primarily intended for SemaphoreUI task types that use SSH as part of their normal execution path,
especially Ansible tasks.

Other task types may also benefit if they explicitly invoke SSH-based tools such as `ssh`, `scp`, `sftp`, or tooling
that honors `SSH_AUTH_SOCK`. However, local script runners such as Bash, Python, or PowerShell do not need an external
SSH agent unless the script itself performs SSH-based remote access.

The initial design assumes a Unix-like runner environment where SSH agent sockets are represented as filesystem paths
and passed through the standard `SSH_AUTH_SOCK` environment variable. That fits typical Linux, Unix, and macOS OpenSSH
behavior, and it also fits common containerized SemaphoreUI runner deployments. Windows support may require additional
design work because SSH agent integration may use different socket or named-pipe behavior depending on the runtime
environment.

Native Windows runner support is out of scope for the initial design. Windows OpenSSH agent integration may use named
pipes or other platform-specific behavior rather than Unix-domain socket paths. Supporting native Windows runners would
require a separate compatibility design.

Windows target administration may also be better served by Windows-native mechanisms such as domain or Entra-backed
identity, PowerShell remoting, managed service accounts, LAPS, Intune Endpoint Privilege Management, or other
policy-based endpoint management tools. This design focuses on SSH-based automation paths, especially Unix-like runners
and Ansible/OpenSSH workflows.

## Core Idea

In this model, SemaphoreUI does not directly manage or expose the final SSH credential used during a task run. Instead,
SemaphoreUI starts an external agent process. That agent provides a Unix-domain socket compatible with the standard
`ssh-agent` protocol. Tools used by the task runner, such as `ssh`, `scp`, `sftp`, and Ansible itself, use that socket
through the normal `SSH_AUTH_SOCK` mechanism.

The external agent may use ordinary SSH keys, SSH certificates, hardware-backed keys, short-lived generated keys, or
some combination of those mechanisms. The important point is that credential behavior can be moved out of SemaphoreUI
and into a purpose-built security component.

The external agent interface should be credential-type neutral. It should allow SemaphoreUI to delegate runtime SSH
credential handling to an external process, whether that process uses ordinary SSH keys, SSH certificates,
hardware-backed keys, HashiCorp Vault, a cloud signing service, or another backend.

## Why Use an External Agent?

SemaphoreUI already supports SSH keys, but static SSH keys have some awkward security properties:

- A private key may remain valid for months or years.
- If a private key is copied, it may be difficult or impossible to know that the copy exists.
- If a user can run arbitrary or semi-arbitrary automation with access to a stored private key, it may be easy for
  that job to expose the key accidentally or deliberately. For example, a trivial task could print, copy, upload, or
  otherwise exfiltrate a private key if the key is materialized into the job environment or filesystem.
- This means the security boundary is not just “who can log into the server,” but also “who can create or modify
  automation that has access to the credential.”
- A copied private key does not carry issuance history, expiration context, approval context, or task context.
- Server logs may show that a key was used, but they may not tell you when access was granted, who requested it, which
  automation job needed it, or why it was valid.
- A copied key may be usable from places where it was never intended to be used.
- A copied key may be usable against many servers if the same public key is deployed widely.
- Rotation can require touching many servers or many SemaphoreUI project settings.
- The automation platform becomes a place where sensitive credential material must be stored.

A static private key stored for automation is especially sensitive because automation systems are designed to run
user-defined commands. If a task runner can materialize the private key into the job environment, then any user who can
author or modify a job using that credential may be able to expose it.

This does not require a sophisticated attack. A malicious or careless job could print the key, copy it to an artifact,
send it over the network, or leave it behind in a workspace.

An external agent improves this because the task receives an agent socket rather than the private key itself. That does
not make misuse impossible, because the job may still be able to ask the agent to sign SSH authentication requests while
the agent is running. But it does reduce the chance that reusable private key material can be copied and used later.

When combined with SSH certificates, this becomes much more powerful.

## Common Alternatives

There are several common ways to manage SSH access for automation systems. The external agent and SSH certificate
approach described in this document is not the only possible model. It is useful to compare it against simpler
approaches so that the tradeoffs are clear.

### Static Keys Stored in the Automation Platform

The simplest approach is to store one or more SSH private keys directly in the automation platform and allow jobs to use
those keys when connecting to servers. This is easy to understand and easy to implement. This approach requires that
you trust the automation platform's secure storage and access policies, and it has several disadvantages:

- The private key may be long-lived, unless you implement some kind of custom rotation policy and tools.
- The same key may be reused across many servers.
- If the private key is copied, it may remain useful for a long time.
- Rotation can require updating many projects, templates, or servers.
- The automation platform becomes a high-value secret store.
- Access control is often tied to who can run the job, not to a more specific credential issuance policy.

This may be acceptable for small or low-risk environments, but it becomes harder to justify as the number of servers,
users, and automation paths grows.

### HashiCorp Vault Secret Storage

SemaphoreUI can integrate with HashiCorp Vault for secret storage. In that model, secrets such as SSH keys, repository
credentials, passwords, and tokens can be stored in Vault instead of SemaphoreUI's database.

This is a meaningful improvement over storing sensitive material directly in the automation platform. Vault can provide
centralized secret management, stronger operational controls, auditing, and rotation workflows.

However, Vault-backed secret storage does not automatically change the SSH authentication model. If the secret stored in
Vault is a long-lived SSH private key, then the task may still be using a long-lived static key. The storage location is
better, but the credential semantics are mostly the same.

In other words, Vault secret storage answers:

> Where should this secret live?

It does not necessarily answer:

> Should this task receive a short-lived SSH credential right now?

HashiCorp Vault can also be used as an SSH certificate authority through its SSH secrets engine. That is closer to the
model described in this document, because Vault can sign SSH public keys and issue short-lived certificates based on
Vault roles and policy.

An external agent could use Vault as its signing backend. In that design, SemaphoreUI would start the agent, the agent
would request a short-lived certificate from Vault, and the task would use the resulting certificate through the normal
`ssh-agent` interface.

This makes Vault complementary to the external agent model rather than a replacement for it.

### Centrally Managed `authorized_keys`

Another common approach is to centrally manage public keys and distribute them to servers.

For example, an organization might keep approved SSH public keys in a Git repository. Servers periodically pull the
latest version of that repository and install the appropriate keys into `authorized_keys` files.

This has some real advantages:

- It is simple.
- It uses standard OpenSSH behavior.
- Public keys are not secret.
- Changes can be reviewed through normal Git workflows.
- Servers can converge toward a known approved key set.
- It avoids manually editing `authorized_keys` on every server.

However, this model still has important limitations:

- The corresponding private keys are usually long-lived.
- Once a key is authorized on a server, it remains useful until removed and until the server receives the update.
- Revocation depends on server polling frequency and successful update execution.
- Access is usually controlled by key presence, not by a short-lived, per-run authorization decision.
- It can be difficult to express temporary access, task-specific access, or approval-based access.
- A broadly deployed public key can create a large blast radius if the private key is compromised.
- Audit logs may show which key was used, but not necessarily which automation job, approval, or policy decision caused
  that access.

This approach is often a reasonable improvement over manually managed keys, especially when an organization wants a
straightforward way to keep public keys synchronized. But it is still fundamentally a distributed static-key model.

### SSH Certificates with an External Agent

The SSH certificate and external agent model changes the access pattern.

Instead of asking:

> Is this public key installed on this server?

the system can ask:

> Should this task, user, project, principal, source address, and trust domain receive a short-lived credential right
> now?

That allows access to be more dynamic and policy-driven.

Compared with centrally distributed `authorized_keys`, this approach can provide:

- Short-lived credentials.
- Per-run credential issuance.
- Principal restrictions.
- Source address restrictions.
- Trust-domain separation.
- Better audit metadata through certificate key IDs and serial numbers.
- Reduced need to distribute individual public keys to every server.
- Easier emergency containment through short lifetimes and scoped trust.
- Optional integration with MFA, approvals, or external identity systems.

The tradeoff is that the certificate-based model requires more design work. The CA must be protected. The signing
process must enforce policy correctly. Servers must be configured to trust the appropriate CA public keys. The external
agent must be implemented carefully.

In other words, centrally managed `authorized_keys` is operationally simple, while SSH certificates move more of the
complexity into a central policy and issuance layer. That added complexity can be worthwhile when the goal is narrower,
auditable, time-limited automation access.

## External Agent Capabilities

An external agent is useful because it changes how SSH credentials are selected, exposed, and controlled at task
runtime. Some of these benefits apply to ordinary SSH keys, while others become stronger when the agent uses SSH
certificates.

### Keep Private Keys Out of the Job Environment

SemaphoreUI can launch a task without storing the final private key that will be used for SSH authentication.

The private key may be:

- Generated temporarily in memory.
- Stored in a hardware-backed provider.
- Held by a separate signing or identity system.
- Exposed only through a constrained agent process.

This reduces the risk created by storing long-lived SSH private keys directly in the automation platform.

A well-designed external agent should avoid writing private key material to disk, even temporarily.

This matters because temporary files have a bad habit of becoming permanent evidence. They can be left behind by
crashes, copied into backups, exposed through debugging, or recovered by someone with filesystem access.

In the strongest version of this model:

- A temporary keypair is generated in memory.
- The public key is signed by a trusted CA.
- The private key remains only in the agent process.
- The certificate expires shortly after the task run.
- The agent exits and the key disappears.

### Dynamic Multi-Identity Agent

An external SSH agent does not need to expose only one SSH identity.

This is useful even when the system is not using SSH certificates. The agent can expose a scoped set of ordinary SSH
keys, SSH certificates, hardware-backed identities, or any combination of those credentials for a particular task run.

For example, a task run may need to connect to several servers that do not all use the same credential. Instead of
forcing the task template to use one static SSH key, the external agent can assemble the credential set at runtime.

The agent might expose:

- One SSH key per target server.
- One SSH key per server group.
- One SSH certificate per trust domain.
- One SSH certificate per required principal.
- A hardware-backed identity for especially sensitive targets.
- A temporary generated identity for a specific run.

In this model, the SSH client tools used by Ansible, such as `ssh`, `scp`, and `sftp`, interact with the agent through
the normal `SSH_AUTH_SOCK` mechanism. The agent offers the identities it has made available for that task, and the SSH
client uses an acceptable identity during authentication.

This creates a flexible model that is difficult to express with a simple static-key configuration.

For example:

- A task run targets several servers.
- The servers require different SSH identities.
- The agent receives task context from SemaphoreUI.
- The agent determines which identities are allowed for that task.
- The agent loads or obtains only those identities.
- SSH selects from the identities exposed by the agent during connection.

This can support dynamic trust grouping without requiring SemaphoreUI itself to understand every server-to-key mapping.

The credential set can be assembled at runtime from policy, inventory, target hostname, requested principal, task
template, requesting user, environment, or other context.

This provides a useful middle ground:

- More flexible than one static key attached to a task.
- Useful with either plain SSH keys or SSH certificates.
- Compatible with ordinary OpenSSH and Ansible behavior.
- Able to support dynamic server groups without changing every task template.

This model does not provide all of the security advantages of SSH certificates if it uses ordinary long-lived SSH keys.
In particular, ordinary keys may still be long-lived and may not carry issuance metadata, expiration, principals, or
certificate restrictions. However, the external agent still improves runtime credential handling by avoiding a single
static credential model and by allowing policy to decide which identities are exposed for each task run.

### Centralized Runtime Policy

The external agent can become the policy enforcement point for SSH credential issuance.

For example, it can decide:

- Which SemaphoreUI users may run as which SSH principals.
- Which task templates may access which trust domains.
- Which projects may reach production systems.
- Whether a task requires approval.
- Whether a user must complete MFA before a certificate is issued.
- Whether access is allowed only during certain maintenance windows.
- Whether a certificate should be valid for 5 minutes, 30 minutes, or some other period.

This is especially important because SemaphoreUI project access and SSH credential access are not always the same thing.

A user may be allowed to run a task template, but that does not necessarily mean they should receive an unrestricted SSH
credential. The external agent can enforce that distinction.

### MFA and Out-of-Band Approval

Because the external agent controls credential availability, it can integrate with additional access controls.

Examples include:

- MFA challenge before issuing a certificate.
- Approval workflow before production access.
- Integration with enterprise access tools.
- Integration with hardware-backed identity such as a YubiKey.
- Time-limited break-glass access.
- Policy checks against an external identity provider.

The SSH server does not need to know about these systems directly. It only needs to trust the SSH CA and enforce the
certificate restrictions.

### Better Audit Context

An external agent can create an audit record when it decides which identities to expose for a task run.

If the agent uses ordinary SSH keys, the audit record can show which keys were made available, to which task, and under
what policy.

If the agent uses SSH certificates, the audit trail can be even stronger because each certificate issuance can be logged
as a discrete access event.

Useful audit fields include:

- Time of issuance or identity exposure.
- Requesting user.
- SemaphoreUI project.
- SemaphoreUI task template.
- SemaphoreUI task/run ID.
- Requested principal.
- Requested trust domain.
- Credential type.
- Credential identifier.
- Certificate validity period, if applicable.
- Certificate serial number, if applicable.
- Certificate key ID, if applicable.
- Source address restrictions, if applicable.
- Approval or MFA status, if applicable.

The SSH server logs should also be useful enough to connect a login back to the credential, certificate, or task run.

### Compatibility with Existing OpenSSH and Ansible Behavior

The external agent model works because it uses the standard `ssh-agent` protocol and the normal `SSH_AUTH_SOCK`
environment variable.

From the perspective of OpenSSH, Ansible, `scp`, and `sftp`, the agent is just an SSH agent. These tools do not need to
know whether the agent is backed by ordinary keys, SSH certificates, hardware-backed identities, Vault, or another
signing system.

That is one of the main advantages of this design: it extends the authentication model without requiring Ansible,
OpenSSH, or playbooks to be rewritten.

## SSH Certificate Capabilities

SSH certificates provide several capabilities that are useful for automation.

### SSH CA Background

OpenSSH supports certificate-based authentication. This is built into OpenSSH and does not require replacing the SSH
server.

There are two related but separate uses of SSH certificates:

1. **User certificates**
    - Used to authenticate a user or automation identity to a server.
    - The client presents a public key plus a certificate signed by a trusted SSH certificate authority.
    - The server trusts the CA, not the individual public key.

2. **Host certificates**
    - Used to authenticate the server to the client.
    - The client trusts a host CA instead of storing individual host keys for every server.

This document is primarily concerned with **user certificates** for automation, because that is the part that can
replace long-lived private keys used by SemaphoreUI jobs.

With user certificates, each server is configured to trust one or more SSH CA public keys. For example, the server may
have a trusted CA configured through `TrustedUserCAKeys`.

When a client connects, it presents:

- A private key it controls.
- A public key certificate signed by the trusted CA.

The certificate says, in effect:

> This public key is allowed to authenticate as one or more named principals, during this time window, subject to these
> restrictions, because it was signed by this trusted CA.

That means the server does not need to know the individual key ahead of time. It only needs to trust the CA and decide
which principals are valid for the target account.

### Short Credential Lifetimes

Certificates can have explicit validity windows.

For example, a certificate could be valid only for the expected length of an Ansible run plus a small buffer. If the
private key or agent socket is captured, the credential becomes useless after the certificate expires.

This is a major improvement over a static SSH private key that might remain valid until someone remembers to rotate it.

### Principal Restrictions

SSH certificates contain one or more principals.

For user certificates, a principal usually represents an identity that the server is willing to accept for login. In
simple environments, the principal may match the Unix username, such as `ansible`, `deploy`, or `root`.

More advanced environments can use `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand` to map trusted
certificate principals to local accounts.

This allows a certificate to say:

> This key may authenticate only as these specific principals.

That is much better than a generic SSH key that can be dropped into `authorized_keys` for many accounts and used
broadly.

### Source Address Restrictions

OpenSSH user certificates support a `source-address` critical option.

This can restrict where the certificate may be used from. For example, a certificate could be valid only when the SSH
connection originates from a known automation runner subnet.

This is useful because it limits the value of stolen credential material. Even if someone obtains a private key and
matching certificate, the server can reject it if the connection does not come from an approved source address.

### Critical Options

SSH certificates can contain critical options. A critical option must be understood and enforced by the SSH server, or
the certificate is rejected.

Useful critical options include:

- `source-address`
    - Restrict the client source addresses from which the certificate may be used.

- `force-command`
    - Force the server to run a specific command when the certificate is used.

For general Ansible automation, `force-command` may be too restrictive, because Ansible needs to run many different
commands. However, it may be useful for narrower automation cases where the credential should only run a specific
wrapper script.

### Extensions

SSH certificates can also contain extensions that control what the session is allowed to do.

Common extensions include:

- `permit-pty`
- `permit-X11-forwarding`
- `permit-agent-forwarding`
- `permit-port-forwarding`
- `permit-user-rc`

For automation credentials, many of these should usually be disabled unless there is a specific need.

For example, an Ansible run generally does not need X11 forwarding. It may not need agent forwarding. It may not need a
pseudo-terminal unless privilege escalation or a specific command requires one.

This gives the certificate authority a way to issue credentials that are narrower than a normal login key.

### Key IDs, Traceability, and Auditability

SSH certificates include a key ID field, validity period, principals, and other metadata that can make automated SSH
access much easier to trace.

This is one of the major advantages of SSH certificates over static keys.

With a static SSH private key, the key may exist for months or years. If it is copied, the copy may be indistinguishable
from the original. Server logs may show that the key was used, but they may not clearly answer:

- When was this credential issued?
- Who or what requested it?
- Which automation job needed it?
- What approval or policy decision allowed it?
- How long was it supposed to be valid?
- Which trust domain or server group was it intended for?

With SSH certificates, each issued certificate can be treated as a discrete access event.

The signing system can log:

- The time the certificate was issued.
- The requesting user or automation identity.
- The SemaphoreUI project.
- The task template.
- The task or run ID.
- The requested principal.
- The requested trust domain.
- The certificate serial number.
- The certificate key ID.
- The certificate validity period.
- Any source address restrictions.
- Any approval, MFA, or policy decision involved.

The certificate key ID can also be designed to include useful identifying information, such as the SemaphoreUI project,
task template, run ID, and requesting user.

This makes access traceability much more direct. Instead of trying to infer why a long-lived key was accepted, we can
record exactly when a short-lived credential was issued and what policy decision caused it to exist.

That does not just improve security. It also improves operations, incident response, and accountability.

### Serial Numbers and Revocation

SSH certificates can include serial numbers.

This can support revocation workflows. OpenSSH can use revoked key files to reject specific keys or certificates.

In many automation environments, short certificate lifetimes reduce the need for emergency revocation, because a
certificate may only be valid for minutes. However, revocation is still useful for cases such as:

- A compromised CA signing process.
- A compromised automation runner.
- A certificate issued incorrectly.
- A policy error that needs to be blocked immediately.

### Trust Domains

SSH CAs can be organized into trust domains.

A trust domain is a group of servers that trust the same CA or set of CAs for a particular purpose.

For example:

- Lab servers.
- Production servers.
- Network devices.
- Facilities systems.
- Development systems.
- High-risk or safety-critical systems.

A single organization does not necessarily need one global SSH CA that can access everything. In fact, that may be
undesirable.

Instead, different server groups can trust different CA public keys. The external agent or certificate issuer can then
enforce policy about which users, tasks, or projects are allowed to obtain certificates for each trust domain.

This reduces blast radius. If one CA, policy path, or automation identity is compromised, it does not automatically
imply access to every server.

## How It Works

At a high level, the flow is:

1. SemaphoreUI starts a task run.
2. Instead of using only its internal SSH key handling, SemaphoreUI starts an external SSH agent.
3. The external agent receives task context from SemaphoreUI.
4. The agent prepares one or more SSH identities for the task run.
5. The agent returns the path to a Unix-domain socket compatible with `ssh-agent`.
6. SemaphoreUI sets `SSH_AUTH_SOCK` for the task environment.
7. Ansible, `ssh`, `scp`, and related tools use the agent socket normally.
8. The SSH server validates the presented identity using normal OpenSSH behavior.
9. When the task completes, SemaphoreUI stops the external agent.
10. Any temporary key material is destroyed or allowed to expire.

If the identity is an ordinary SSH key, the server validates it against `authorized_keys` or another configured
public-key authorization mechanism.

If the identity is an SSH certificate, the server validates the certificate against its trusted SSH CA configuration and
enforces the certificate principals, validity period, critical options, and extensions.

## Example Implementation Patterns

The external agent interface should not require one specific credential backend. The same interface can support several
implementation patterns.

### Static-Key Agent

A static-key agent can load one or more existing SSH private keys and expose them through the `ssh-agent` protocol.

This is closest to traditional SSH key handling, but it can still provide some useful separation. For example, the agent
can decide which keys to expose for a particular task run instead of giving every task access to the same stored
credential.

This model does not provide all of the benefits of SSH certificates. The keys may still be long-lived, and access may
still depend on `authorized_keys` entries deployed to servers. However, it can be a practical migration step.

### Dynamic Multi-Key Agent

A dynamic multi-key agent can assemble a scoped set of SSH identities for a task run.

For example, it might load one key per target server, one key per server group, or one key per environment. This allows
a task to connect to different hosts using different credentials without requiring the task template to be tied to one
static key.

The important design rule is that the agent should expose only the identities needed for the current task run.

### SSH CA-Signing Agent

An SSH CA-signing agent can generate a temporary keypair, request a short-lived SSH certificate from a signing service,
and expose the temporary private key and certificate through the agent socket.

One possible flow is:

1. The external agent starts for a specific SemaphoreUI task run.
2. The agent receives task context from SemaphoreUI.
3. The agent authenticates to a signing service or policy engine.
4. The agent generates a temporary SSH keypair in memory.
5. The agent sends the public key to the signing service.
6. The signing service checks policy.
7. The signing service returns a short-lived SSH certificate.
8. The agent exposes the temporary private key and certificate through the `ssh-agent` protocol.
9. The task uses SSH normally.
10. When the task ends, the agent exits and the temporary private key is lost.

This pattern provides the strongest alignment with short-lived, auditable, policy-driven automation access.

### Hardware-Backed Agent

A hardware-backed agent can expose SSH identities backed by a hardware token or hardware security module.

This may be useful for especially sensitive environments where private key material should not be exportable. The details
depend heavily on the hardware and signing mechanism, but the task runner can still interact with the agent through the
normal `SSH_AUTH_SOCK` interface.

### Vault-Backed Agent

A Vault-backed agent can use HashiCorp Vault as a secret source, signing backend, or policy enforcement point.

For example, the agent might retrieve an SSH key from Vault, request an SSH certificate from Vault's SSH secrets engine,
or use Vault policy to decide whether a task should receive a credential.

This makes Vault complementary to the external agent model. Vault can provide secret storage or certificate issuance,
while the external agent bridges that capability into SemaphoreUI task execution through the standard SSH agent
interface.

## Key Design Philosophies

### Keep Secret Material Out of Files

The external agent should avoid writing private keys, certificates, tokens, or other sensitive material to disk unless
there is a deliberate and well-documented reason.

In particular:

- Do not write temporary private keys to `/tmp`.
- Do not leave private keys in task working directories.
- Do not pass private keys through command-line arguments.
- Do not log private keys, tokens, or full certificates unless explicitly safe.
- Be careful with environment variables, because they may be visible through process inspection or logs.

The safest private key is one that exists only briefly and only in memory.

### Prefer Short-Lived Certificates

Certificates should be valid only as long as needed.

A reasonable pattern is:

- Expected task duration.
- Plus a small buffer.
- With a maximum allowed lifetime enforced by policy.

Long-lived certificates defeat much of the purpose of using certificates in the first place.

### Limit Principals

Certificates should include only the principals required for the task.

Avoid issuing certificates that can authenticate as many users unless the task truly requires that.

For automation, prefer narrow principals such as:

- `ansible`
- `deploy`
- `backup`
- `monitoring`

Avoid issuing certificates that can authenticate as `root` unless there is a clear reason.

If privilege escalation is needed, it may be better to authenticate as a constrained automation user and use controlled
`sudo` rules.

### Limit Trust Domains

Do not assume one CA should be trusted everywhere.

Use separate trust domains where appropriate. For example, production systems should not necessarily trust the same CA
path used for lab systems.

Trust domains make it possible to reason about blast radius.

### Disable Unneeded SSH Features

Certificates used for automation should not automatically permit every SSH feature.

Consider disabling features such as:

- Agent forwarding.
- X11 forwarding.
- Port forwarding.
- PTY allocation.

Only enable what the task actually needs.

### Treat the Agent as Security-Critical

The external agent is part of the authentication boundary.

If the agent is careless, the whole system becomes careless.

The agent should:

- Validate its inputs.
- Avoid leaking secrets.
- Clean up its socket.
- Exit when the task is complete.
- Refuse unsafe configurations.
- Avoid exposing more identities than necessary.
- Protect its Unix-domain socket permissions.
- Avoid accepting connections from unrelated users or processes.
- Fail closed when policy cannot be checked.

## Security Considerations

This architecture improves several security properties, but it does not eliminate the need for careful design.

Important considerations include:

- The CA private key must be strongly protected if SSH certificates are used.
- The signing service must enforce policy correctly if credentials are issued dynamically.
- The external agent must not expose credentials to other users on the same host.
- The socket path must be protected by filesystem permissions.
- Task context provided to the agent must be trustworthy.
- Certificate lifetime should be short if SSH certificates are used.
- Certificate principals should be narrow if SSH certificates are used.
- Trust domains should be explicit.
- Logs must not leak secrets.
- Revocation should be considered, even if short lifetimes reduce the need for it.
- Server-side SSH configuration must actually enforce the intended key, CA, principal, and authorization policy.

This design should not be treated as “magic security dust.” It is a way to move from broad, static credentials toward
narrower, time-limited, policy-driven credentials.

That is a meaningful improvement, but only if the agent and any signing process are implemented carefully.

## Relationship to SemaphoreUI

SemaphoreUI remains responsible for scheduling and running automation tasks.

The external SSH agent is responsible for providing SSH credentials to those tasks.

This separation is useful because SemaphoreUI does not need to know every detail of the organization's SSH credential
policy. It only needs to know how to start the external agent and how to provide the resulting `SSH_AUTH_SOCK` to the
task environment.

The external agent can then implement organization-specific behavior without requiring SemaphoreUI itself to become a
full credential broker.

This also means the same general interface could support different backends:

- Static SSH keys.
- Dynamic multi-key selection.
- Short-lived generated keys.
- SSH CA-signed keys.
- Hardware-backed keys.
- Cloud signing services.
- Vault-backed signing or secret retrieval.
- MFA-gated certificate issuance.
- Approval-based certificate issuance.
- Environment-specific trust domains.

The interface should be generic enough to support these options without assuming one particular implementation.

## References

The following references explain OpenSSH certificate authentication in more detail:

- [OpenSSH Cookbook: Certificate-Based Authentication](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Certificate-based_Authentication)
- [Red Hat: Distributing and Trusting SSH CA Public Keys](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/sec-distributing_and_trusting_ssh_ca_public_keys)
- [sshca Documentation](https://doc.liw.fi/sshca/sshca.html)
- `ssh-keygen(1)`
- `sshd_config(5)`
- `ssh_config(5)`


# Agent Documentation

## External Agent Interface

The external agent interface defines how SemaphoreUI starts, uses, and stops a task-scoped SSH agent.

The goal is to support custom SSH credential providers without requiring SemaphoreUI to link against provider-specific
code. Instead of implementing a Go plugin API or loading dynamic libraries, SemaphoreUI starts an external executable
using a small, structured process contract.

The external agent executable is not a library plugin. It is a task-scoped credential process.

For each task run, SemaphoreUI can:

1. Load the external agent configuration from the SemaphoreUI Key Store.
2. Start the configured external agent executable.
3. Pass task context and agent configuration to the agent.
4. Wait for the agent to report that it is ready.
5. Receive the path to an `ssh-agent` compatible Unix-domain socket.
6. Set `SSH_AUTH_SOCK` for the task runtime environment.
7. Run the task normally.
8. Stop the external agent when the task finishes.
9. Clean up temporary runtime files owned by SemaphoreUI.

This keeps the interface small. SemaphoreUI does not need to know whether the agent is using static SSH keys, SSH
certificates, HashiCorp Vault, a cloud signing service, a hardware-backed key, or some other credential source. It only
needs to know how to start the agent, how to receive an agent socket, and how to stop the process.

## Agent Configuration

External agent configuration is stored in the SemaphoreUI Key Store.

From SemaphoreUI's point of view, this configuration is an opaque text document. SemaphoreUI stores it securely and
passes it to the external agent, but it does not interpret provider-specific fields.

For SSH CA-based agents, the Key Store entry may include configuration or credentials needed to request a signed SSH
certificate. For example, this might include a signing service URL, a trust domain, a principal mapping, a Vault role, or
credentials used to authenticate to the signing backend.

_Agent-specific configuration may itself be sensitive._ For that reason, this design continues to rely on SemaphoreUI's
existing secure secret storage mechanisms for storing and protecting external agent configuration.

This design allows each external agent implementation to define the configuration it needs without SemaphoreUI having an
opinion about the shape of that configuration. JSON is a good default for new agents, but the interface does not require
the configuration document to be JSON.

The complete configuration blob is passed to the agent on standard input when the agent is started.

For example, one agent might require:

- A signing service URL.
- A trust domain name.
- A default SSH principal.
- A maximum certificate lifetime.
- A Vault role name.
- A hardware token slot.
- A list of allowed identity mappings.

Another agent might require only:

- A list of key references.
- A runtime directory.
- A default username.

SemaphoreUI should define only the small amount of configuration required by the external agent interface itself. All
provider-specific configuration belongs to the external agent.

For new external agents, JSON is probably the most practical configuration format. The exact shape will depend on the
specific agent. For example:

```json
{
  "default_principal": "ansible",
  "max_ttl_seconds": 1800,
  "signing_service_url": "https://ssh-ca.example.edu"
}
```

# Agent Documentation

## External Agent Interface

The external agent interface defines how SemaphoreUI starts, uses, and stops a task-scoped SSH agent.

The goal is to support custom SSH credential providers without requiring SemaphoreUI to link against provider-specific
code. Instead of implementing a Go plugin API or loading dynamic libraries, SemaphoreUI starts an external executable
and communicates with it using a small, structured process protocol.

The external agent executable is not a library plugin. It is a task-scoped credential process.

For each task run, SemaphoreUI can:

1. Load the external agent configuration from the SemaphoreUI Key Store.
2. Start the configured external agent executable.
3. Send task context and agent configuration to the agent.
4. Wait for the agent to report that it is ready.
5. Receive the path to an `ssh-agent` compatible Unix-domain socket.
6. Set `SSH_AUTH_SOCK` for the task runtime environment.
7. Run the task normally.
8. Ask the external agent to shut down when the task finishes.
9. Clean up temporary runtime files owned by SemaphoreUI.

This keeps the interface small. SemaphoreUI does not need to know whether the agent is using static SSH keys, SSH
certificates, HashiCorp Vault, a cloud signing service, a hardware-backed key, or some other credential source. It only
needs to know how to start the agent, how to receive an agent socket, and how to ask the agent to stop.

## Agent Configuration

External agent configuration is stored in the SemaphoreUI Key Store.

From SemaphoreUI's point of view, this configuration is an opaque text document. SemaphoreUI stores it securely and
passes it to the external agent, but it does not interpret provider-specific fields.

For SSH CA-based agents, the Key Store entry may include configuration or credentials needed to request a signed SSH
certificate. For example, this might include a signing service URL, a trust domain, a principal mapping, a Vault role, or
credentials used to authenticate to the signing backend.

_Agent-specific configuration may itself be sensitive._ For that reason, this design continues to rely on SemaphoreUI's
existing secure secret storage mechanisms for storing and protecting external agent configuration.

This design allows each external agent implementation to define the configuration it needs without SemaphoreUI having an
opinion about the shape of that configuration. The configuration may be JSON, YAML, TOML, environment-style text, or any
other text format the agent understands.

For new agents, JSON is probably a practical default. For example, one agent might expect configuration like this:

    {
      "default_principal": "ansible",
      "max_ttl_seconds": 1800,
      "signing_service_url": "https://ssh-ca.example.edu"
    }

Another agent might expect environment-style text:

    TRUST_DOMAIN=lab
    DEFAULT_PRINCIPAL=ansible
    MAX_TTL_SECONDS=1800
    SIGNING_SERVICE_URL=https://ssh-ca.example.edu

SemaphoreUI should not parse, validate, transform, partially interpret, or display provider-specific configuration. It
should treat the configuration as an opaque body and send it to the agent as part of the control protocol.

## Agent Trust Boundary and Runtime Context

The external agent receives two different kinds of input from SemaphoreUI:

1. Provider-specific configuration from the Key Store.
2. Runtime context from the SemaphoreUI task execution environment.

These inputs should be treated differently.

Provider-specific configuration is opaque to SemaphoreUI. SemaphoreUI stores it securely and passes it to the agent, but
does not interpret its contents.

Runtime context, such as task ID, project ID, template ID, inventory ID, user ID, and runtime directory, is different.
These values are known to SemaphoreUI and may be passed to the agent through command-line arguments using a limited set
of supported substitutions.

For example, an external agent configuration may include arguments such as:

    --runtime-dir {{ .RuntimeDir }}
    --task-id {{ .TaskID }}
    --project-id {{ .ProjectID }}
    --template-id {{ .TemplateID }}
    --user-id {{ .UserID }}

These values are trusted within the SemaphoreUI task execution and credential boundary. In other words, the external
agent may use them for logging, traceability, runtime file placement, and policy decisions if it trusts the SemaphoreUI
instance that launched it.

However, these values are not independent cryptographic proof of identity. They are assertions provided by SemaphoreUI.

For example, `{{ .UserID }}` identifies the SemaphoreUI user associated with the task run. An external agent may choose
to use that value when deciding whether the task is allowed to request a particular SSH principal, trust domain, or
credential type. That is reasonable if the agent trusts SemaphoreUI as the policy-calling system.

The important security distinction is this:

- SemaphoreUI is trusted to report its own task execution context.
- The external agent is responsible for deciding how much it trusts that context.
- The external agent must still enforce its own policy before exposing credentials.
- Runtime context should not be treated as a substitute for authentication to an external signing service, Vault,
  hardware token, or other credential backend.

This allows the agent to make useful decisions such as:

- User `123` may request the `ansible` principal in the `lab` trust domain.
- This task template may use staging credentials but not production credentials.
- This project may access one server group but not another.
- This task run should be recorded in certificate key IDs, audit logs, or signing requests.

This is also why runtime context should be passed separately from provider-specific configuration. SemaphoreUI cannot
safely inject runtime values into the opaque configuration body because it does not know whether the body is JSON, YAML,
TOML, environment-style text, or some other format.

The `args` field provides a controlled way to pass SemaphoreUI-owned runtime context without requiring SemaphoreUI to
understand or modify provider-specific configuration.

## Agent Control Protocol

SemaphoreUI communicates with the external agent over the agent process's standard input and standard output.

The control protocol is a persistent, framed request/response protocol. It is inspired by HTTP-style request semantics,
but it is not HTTP and is not exposed over a network socket.

Standard input carries requests from SemaphoreUI to the agent. Standard output carries responses from the agent to
SemaphoreUI. Standard error is reserved for logs and diagnostic output.

This avoids requiring the external agent to expose a control TCP port, Unix-domain control socket, named pipe, or other
listener. The only socket required by this design is the SSH agent socket returned to SemaphoreUI and used by
OpenSSH-compatible tools through `SSH_AUTH_SOCK`.

Version 1 defines two control methods:

- `config`
- `shutdown`

The protocol is synchronous in version 1. SemaphoreUI sends one request, waits for the corresponding response, and then
sends the next request when appropriate. Only one request is outstanding at a time.

## Message Format

Each control message begins with a text header block, followed by an optional body.

A blank line separates the headers from the body.

The `Content-Length` header specifies the number of body bytes that follow the blank line. If no body is present,
`Content-Length` must be `0`.

A request message has this shape:

    AGENT/1 REQUEST
    Id: 1
    Method: config
    Content-Length: 87

    <87 bytes of request body>

A response message has this shape:

    AGENT/1 RESPONSE
    Id: 1
    Status: 200
    Message: OK
    Content-Length: 36

    /run/semaphore/agents/123/agent.sock

The `Id` value is used to match responses to requests. Version 1 is synchronous, but including an ID keeps the protocol
clear and leaves room for future extension.

The `Status` value follows familiar HTTP-style status code conventions:

- `200` indicates success.
- `4xx` indicates that the request was understood but rejected.
- `5xx` indicates that the agent failed while trying to process the request.

SemaphoreUI should not require agents to use a large or exact set of status codes. In version 1, SemaphoreUI only needs
to distinguish success from failure. A `200` response means success. Any non-`200` response means failure.

The response body for an error should contain a user-readable explanation that SemaphoreUI may display in task output or
error details.

## Configuration Request

SemaphoreUI sends a `config` request after starting the external agent.

The body of the `config` request is the opaque configuration blob retrieved from the SemaphoreUI Key Store. SemaphoreUI
does not interpret this body.

Example request:

    AGENT/1 REQUEST
    Id: 1
    Method: config
    Content-Length: 87

    TRUST_DOMAIN=lab
    DEFAULT_PRINCIPAL=ansible
    MAX_TTL_SECONDS=1800

If configuration succeeds, the agent returns a `200` response. The response body contains the path to the Unix-domain
socket that SemaphoreUI should use as `SSH_AUTH_SOCK`.

Example successful response:

    AGENT/1 RESPONSE
    Id: 1
    Status: 200
    Message: OK
    Content-Length: 36

    /run/semaphore/agents/123/agent.sock

After receiving this response, SemaphoreUI sets `SSH_AUTH_SOCK` to the response body value and starts the task runner.

If configuration fails, the agent returns a non-`200` response. The response body should contain a user-readable
explanation.

Example error response:

    AGENT/1 RESPONSE
    Id: 1
    Status: 403
    Message: Permission Denied
    Content-Length: 73

    Task template is not allowed to request the production trust domain.

SemaphoreUI should fail the task if the `config` request fails.

## Shutdown Request

When the task finishes, SemaphoreUI sends a `shutdown` request.

Example request:

    AGENT/1 REQUEST
    Id: 2
    Method: shutdown
    Content-Length: 0

The agent should respond and then exit cleanly.

Example response:

    AGENT/1 RESPONSE
    Id: 2
    Status: 200
    Message: OK
    Content-Length: 0

During shutdown, the agent should:

- Stop accepting new SSH agent requests.
- Close the SSH agent socket.
- Remove socket files it created.
- Remove temporary runtime files it created.
- Release any external leases or sessions if applicable.
- Exit with status `0`.

If the agent does not exit after a shutdown request, SemaphoreUI may fall back to process termination. Signals are
fallback cleanup mechanisms, not the primary graceful shutdown protocol.

## Stream Rules

Version 1 is strictly synchronous. SemaphoreUI sends one request and waits for exactly one response before sending
another request. Because only one request may be outstanding at a time, messages do not include request IDs.

The agent must write only protocol responses to standard output.

Logs, warnings, and diagnostic messages must be written to standard error so they do not corrupt the response stream.

The agent must not write private keys, access tokens, provider secrets, or unredacted sensitive configuration to standard
output or standard error.

SemaphoreUI should treat malformed responses as agent startup or protocol failures.

SemaphoreUI should also impose reasonable timeouts. For example:

- A timeout while waiting for the `config` response.
- A timeout while waiting for the `shutdown` response.
- A timeout while waiting for the agent process to exit after shutdown.

If a timeout occurs, SemaphoreUI may fail the task or fall back to process termination depending on where the failure
occurred.

## Security Notes

The external agent protocol is part of the SSH authentication boundary and should be treated as security-sensitive.

Important security rules include:

- Do not pass secrets through command-line arguments.
- Do not pass sensitive provider configuration through environment variables.
- Do not expose a control TCP port or control socket unless a future design explicitly requires it.
- Treat the Key Store configuration body as sensitive.
- Protect the returned SSH agent socket with restrictive filesystem permissions.
- Expose only the identities needed for the task run.
- Fail closed if policy cannot be checked.
- Clean up socket files and temporary runtime files when the task finishes.

Anything that can access the returned `SSH_AUTH_SOCK` may be able to use the identities exposed by the agent while the
task is running. For that reason, socket location, filesystem permissions, process ownership, and cleanup behavior all
matter.