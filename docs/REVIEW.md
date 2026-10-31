# Development review

## Fixed in this pass

- XPC completion could run twice: invalidating a successfully replied connection
  triggered the failure handler. Added a locked completion-once gate and timeout.
- IPC errors falsely asserted no action occurred. A timeout can happen after an
  action; wording now correctly reports unknown outcome.
- Action errors were discarded before refreshing status. They are now displayed.
- A combined toggle inferred action from display text and offered Enable on error.
  Replaced with distinct Enable and Disable actions and separate capabilities.
- Old asynchronous status replies could overwrite newer state. Added generation
  checks; action initiation invalidates previous status requests.
- Controller status accepted a loaded anchor without verified root reachability.
  It now also requires the backend's gate_verified result; refresh verifies status.

## Added, fake-kernel tests only

Injected-runner PF driver requires the first root filter rule to be this project's
quick anchor. It does not edit /etc/pf.conf. Syntax check and load are scoped to the
project anchor with stdin; removal empties only that anchor. Enable reference
acquisition records an uncertain/pending state before -E and refuses to repeatedly
acquire when a token is missing or stale. Release uses only the recorded -X token.
No global flush or -d command is used. These tests do not validate real macOS PF.

## Still release-blocking

- No authenticated signed XPC listener or authorized privileged operations.
- A boot-bound token journal is implemented and offline-tested; integration into
  a privileged service, trusted boot-identity acquisition and same-boot PF/kernel
  restart reconciliation are still missing. Parent state directories must be
  trusted; fsync/atomic replace alone does not prove power-loss durability.
- Real PF state/skip behavior and complete rule equality verification untested.
- No automatic endpoint-update trust/bootstrap mechanism or approval interface.
- No reliable emergency GUI path when the privileged service fails.
- No end-to-end network-change monitoring, health recovery, or boot proof.

The withdrawal warning must remain. There must be no installer/activation path
until these are resolved and a controlled live test is explicitly authorized.
