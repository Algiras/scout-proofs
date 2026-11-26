# Security policy

SCOUT is a reference implementation and a set of formal models. It is not a production service, but reports of flaws in the protocol, the proofs or the code are very welcome.

## Reporting a problem

Please report privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue for something that could put a deployment at risk.

Useful reports include:

- an attack on the protocol that the models or proofs miss, or a property that is stated more strongly than what is proved;
- a divergence between the Rust protocol core and the models;
- a flaw in the code around the core (sealing, proofs of possession, storage, HTTP handling);
- a mistake in the paper.

You can expect an acknowledgement within a week. Fixes to the protocol or the proofs are published in the repository and, where they change the paper, in a new version of the Zenodo record.

## Scope and known limits

The limits of the implementation are listed in [`impl/README.md`](impl/README.md) and in the paper: one broker replica with a file-backed store, no TLS termination in the server itself, a mock provider, an unauthenticated principal in the demo, and no assertion-mediated renewal or delegation supervisor. Reports that only restate these are not vulnerabilities, though ideas for closing them are welcome as ordinary issues.
