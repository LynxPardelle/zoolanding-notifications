# Zoolanding Notifications

Generic server-only outbound transactional email for Zoolanding drafts. Phases 6 and 8 are implemented locally; no AWS resource, SMTP secret, SMTP2GO call, message, or provider activation is created by this repository state.

## Closed MVP boundary

- One SQS worker consumes only raw `notification.requested.v1` messages emitted by Commerce.
- The event contains only opaque IDs, exact immutable `publishedVersionId`, code-owned type/template IDs, a commerce-order source, and three typed bounded values. Email addresses, bodies, credentials, fiscal data, Stripe objects, and provider payloads are rejected.
- Every attempt refreshes Config Registry scope and resolves only the exact event-pinned `_manifest.json` plus `server/notification-policies.json`, verifying path/kind/SHA-256 and the complete policy/type/template/recipient/source tuple before reading a secret. A warm runtime may reuse only an already verified immutable selection keyed by that complete tuple; it never consults the current pointer for the queued event.
- The worker resolves only active `email.smtp` + `send` bindings through the exact AWS_IAM Integrations path. It accepts only adapter `smtp2go-smtp-v1`, `mail.smtp2go.com:465`, implicit TLS, server-owned sender local-parts, and the environment-specific sender domain.
- Test always sends from the server-bound `zoolandingpage.com.mx` domain even when the draft canonical domain differs. Production requires the exact draft canonical domain and a separately audited standalone account/credential activation.
- SMTP and recipient values live in separate exact Secrets Manager paths. Current enabled/scope/lifecycle tags are checked before `GetSecretValue` on every attempt, so revocation overrides an older pinned policy.
- Templates are fixed Spanish `text/plain` messages with one recipient, bounded typed substitution, safe headers, and a stable `Message-ID`. Tracking, HTML, attachments, archive, SMTP2GO API/webhooks, inbound mail, and mailbox UI are absent.

## Delivery semantics

The retained PAY_PER_REQUEST ledger uses only `prepared`, `sending`, `accepted_by_smtp`, `uncertain`, and `failed`, with 90-day TTL on technical records. It stores no address, message body, variables, credentials, secret metadata, or provider text.

`accepted_by_smtp` means the SMTP DATA command was accepted; it is not inbox delivery. Confirmed `4xx` results retry up to the pinned policy maximum of five attempts. Confirmed `5xx` results fail. Authentication `535` and quota `552` open a connection circuit. A timeout, disconnect, TLS ambiguity, worker crash, failed post-accept ledger commit, or stale `sending` lease becomes `uncertain` and is never resent automatically.

Operators must review matching SMTP2GO activity before using `tools/reconcile_delivery.py` to record an opaque approval and either confirm acceptance or authorize one new attempt. A retry is accepted only while the immutable policy's pinned attempt budget still has capacity; an exhausted budget fails closed without reporting success. This is the explicit duplicate/loss trade-off: the service prefers a possible missed notification over a blind duplicate after an ambiguous SMTP result.

Code-owned conditional limits are 20 attempts per draft/minute and 100 per connection namespace/minute. The SQS source uses batch size 1, maximum concurrency 2, partial batch failures, 180-second visibility, and a DLQ after five receives.

## Infrastructure readiness

- CI runs on pushes and pull requests for every branch. There is no AWS `dev` stack, deploy workflow, deployment environment, or SAM deploy profile.
- Test deployment accepts only the protected `dev -> test` promotion; production accepts only `test -> main`. Validation produces a SHA-256 manifest and exact build artifact, while OIDC credentials exist only in the deploy job after the promotion and artifact are reverified.
- Config Registry, Config payload bucket, Commerce notification topic, and Integrations API identifiers are consumed through environment-scoped SSM parameter names. The stack publishes only its worker role ARN, queue ARN, and technical ledger name through environment-scoped plaintext SSM parameters; none is a secret.
- Runtime IAM is read-only for Config and exact immutable descriptors, invokes only the Integrations connection-resolution route, and can read only version-suffixed notification SMTP/recipient secret paths. It has no secret mutation, Config mutation, S3 write/list, or SNS publish permission.
- Queue/DLQ depth and age, Lambda errors/throttles, SMTP circuit, SMTP2GO authentication/quota/documented throttle rejection, and test/live mismatch all alarm through the required operator `AlarmTopicArn`.
- `tools/notification_readiness_smoke.py` performs no send. It reads seven exact SSM identifiers without decryption and emits only `ready`, `missing_input`, `auth_failure`, `configuration_failure`, `provider_failure`, or `propagation_delay`.

## Safe recipient operations

`tools/manage_recipient_secret.py create` reads the address through hidden input, uses `CreateSecret` once, and never prints the value or path. Any change requires a new `recipientSetVersion`, which produces a new path. `revoke` changes only `zoolanding:enabled=false`.

These tools are local operator surfaces. Running them against AWS requires separate explicit authorization; unit tests use fakes and make no AWS call.

## Local verification

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
python -m compileall -q src tools tests
python -m pip_audit --requirement requirements-dev.txt
sam validate --lint
sam build --no-cached
python tests/verify_sam_build.py
python tools/notification_readiness_smoke.py --environment test --region us-east-1
git diff --check
```

## Deployment verdict

**NO-GO for deployment.** The local Phase 8 controls are present, but deployment still requires environment protection/variables, the upstream SSM identifiers, exact OIDC and CloudFormation roles, an operator alarm topic, provisioned and audited per-draft SMTP/recipient secrets, SMTP2GO account and sender-domain evidence, live quota confirmation, failure injection, and end-to-end acceptance/delivery proof. The service intentionally has no API Gateway or AWS `dev` environment.
