# Optional OCI synthetic-lab backend

## Decision

Keep the local WSL backend as ScopeRook's default. Add Oracle Cloud Infrastructure only as an optional, explicitly configured backend for reviewed synthetic fixtures that need more memory, a clean Linux image, or native build tooling. No bounty target, account credential, private program text, or customer data belongs in this backend.

The first useful OCI worker is an ephemeral user-mode application sandbox. It is not suitable for kernel, hypervisor, firmware, malware-detonation, availability, or sandbox-escape testing.

## Account boundary

Create a dedicated `scoperook-labs` compartment. ScopeRook must never receive tenancy-admin credentials. The controller may create, inspect, and terminate only the worker resources in that compartment. The worker identity may read one immutable input object and write one result object; it cannot manage IAM, networking, Compute, or other objects.

Do not run fixtures inside OCI Cloud Shell. Cloud Shell is pre-authenticated to the tenancy and has persistent storage in the home region. It is suitable for a human to launch or destroy the isolated worker, not for executing untrusted fixture code.

## Network boundary

- Put workers in a private subnet with no public IP.
- Add no internet gateway or NAT gateway.
- Permit no inbound traffic.
- Prefer no outbound traffic. If Object Storage transfer is required, use a service gateway and restrict the worker policy to the exact input and result prefixes.
- Bake the reviewed runner into the worker image. Do not install packages during a job.
- Do not make the worker reachable from bounty targets or use it as a scanning origin.

## Job contract

Reuse the local manifest model: a caller supplies only a reviewed lab id. The controller resolves a signed, hash-pinned bundle and rejects caller-provided commands, paths, images, environment variables, URLs, and cloud-init. Every job must run the candidate and its declared negative control.

Each result records the image id, image digest, shape, architecture, region, manifest and entrypoint hashes, resource limits, start and stop timestamps, exit codes, bounded stdout and stderr hashes, isolation self-checks, cleanup result, and whether every control passed. Output is evidence for the synthetic fixture only.

## Lifecycle and cost controls

1. Preflight the compartment, shape, quota, private subnet, image allowlist, input hash, and absolute job deadline.
2. Launch one worker with a tag containing the job id and expiration time.
3. Run the fixed harness with no privileges, a read-only input, an empty secret set, and CPU, memory, process, file, output, and wall-clock limits.
4. Retrieve the bounded result through the private Oracle service path.
5. Terminate the worker and permanently delete its boot volume.
6. Independently verify that no instance, volume, VNIC, or temporary object remains.

Use a compartment quota as the hard resource ceiling. An OCI budget is a delayed soft alert and must not be the only cost control. Start with at most one worker, 2 OCPUs, 12 GB RAM, and a 15-minute absolute lifetime. The exact quota name depends on the chosen shape and region and must be verified before deployment.

OCI Always Free currently makes Arm-based `VM.Standard.A1.Flex` capacity attractive for Python, Java, and architecture-neutral fixtures. Arm is not a valid substitute for x86-specific native behavior. The x86 micro shape has only 1 GB RAM, so larger x86 labs may require paid capacity. Free capacity can also be unavailable or reclaimed.

## Credential handling

The initial deployment should be human-launched from OCI Cloud Shell or the Console. A later desktop integration can use the user's protected OCI CLI profile, but the MCP must receive only backend status and job ids. Never place private keys, session tokens, config contents, OCIDs tied to identity, or signed Object Storage URLs in engagement records, evidence bundles, logs, prompts, or tool results.

## Implementation gates

- The local WSL backend and evidence format pass their tests.
- A dedicated compartment, quota, private subnet, and restricted IAM policies have been reviewed.
- The user approves any paid shape and maximum spend before it is launched.
- A harmless fixture completes, cleanup is independently verified, and the account audit log matches the expected lifecycle.
- Only then may the OCI backend be exposed as a ScopeRook MCP tool.

Until these gates pass, OCI remains a documented design and ScopeRook makes no Oracle API calls.
