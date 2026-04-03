# Security Policy

## Overview
PhishGuard RAG is a phishing detection application that processes user-submitted text, URLs, and email-like content through a FastAPI backend, LangChain pipeline, Groq model access, and a local ChromaDB knowledge base.

This document defines the minimum security expectations for development, deployment, and incident response.

## Security Objectives
- Protect API credentials and other secrets.
- Prevent unauthorized access to analysis and ingestion endpoints.
- Minimize exposure of user-submitted content.
- Keep the knowledge base and model outputs trustworthy.
- Reduce the blast radius of misconfiguration or abuse.

## High-Risk Assets
- `GROQ_API_KEY`
- Any `LANGSMITH_API_KEY`
- The ChromaDB data under `data/processed`
- The raw corpus under `data/raw`
- Feedback and analysis history
- Server logs and tracing output

## Required Controls
### Secrets
- Never commit `.env` files or credentials to source control.
- Load secrets only from runtime environment variables or a secrets manager.
- Rotate keys immediately if exposure is suspected.
- Use separate keys for development, staging, and production.

### Authentication and Authorization
- Protect `/analyze`, `/feedback`, `/stats`, and `/ingest` with authentication.
- Treat `/ingest` as an admin-only operation.
- Restrict access to trusted origins and clients.
- Do not expose admin credentials to the frontend.

### Input Handling
- Enforce request size limits and field length limits.
- Reject malformed or unusually large payloads early.
- Treat all user input and retrieved documents as untrusted.
- Keep prompt-injection defenses layered, not singular.

### Logging and Privacy
- Do not log secrets, tokens, or full sensitive payloads.
- Avoid returning internal stack traces to clients.
- Minimize retention of user-submitted content.
- Redact sensitive fields before log emission where possible.

### Deployment
- Use HTTPS in any non-local environment.
- Place the app behind a reverse proxy or gateway when exposed externally.
- Restrict CORS to approved origins only.
- Run the service with least privilege.

## Incident Response
If a secret is exposed:
1. Revoke the key immediately in the provider console.
2. Replace the secret in the deployment environment.
3. Review logs for unusual usage.
4. Invalidate any dependent credentials if needed.
5. Document the incident and corrective action.

If the knowledge base is poisoned or reset unexpectedly:
1. Stop writes to the vector store.
2. Restore from the most recent known-good backup.
3. Review ingestion access and audit logs.
4. Rebuild the corpus from trusted sources only.

If the API is abused or attacked:
1. Rate limit or block the offending source.
2. Verify authentication and authorization controls.
3. Inspect request logs for payload patterns and volume.
4. Patch the abuse path before restoring normal access.

## Secure Development Expectations
- Review dependencies before upgrading them.
- Run security checks in CI where possible.
- Add tests for authentication, input limits, and error handling.
- Avoid expanding attack surface unless there is a clear need.
- Prefer simple, auditable controls over complex custom logic.

## Reporting a Vulnerability
If you discover a security issue in this repository:
- Do not publish exploit details publicly before coordination.
- Report the issue to the repository owner or maintainer.
- Include the affected file, endpoint, and a short description of impact.
- If a secret may be exposed, request immediate rotation.

## Operational Notes
- Local development may use `http://localhost:8000`, but production must use TLS.
- The `/ingest` endpoint should never be publicly accessible without strong controls.
- The frontend should not depend on third-party resources unless explicitly approved.
- The repository should keep test coverage for the security controls that matter most.

## Review Checklist
Before releasing a change:
- [ ] No secrets are committed
- [ ] Auth is required on sensitive endpoints
- [ ] CORS is restricted
- [ ] Input limits are enforced
- [ ] Errors do not leak internals
- [ ] `/ingest` is admin-only
- [ ] Logs do not contain sensitive content
- [ ] Dependencies were reviewed

## Contact
Maintainers should define a private security contact channel here before production use.
