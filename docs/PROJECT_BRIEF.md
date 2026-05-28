        # Project Brief

        cidrcalc exists to solve a narrow, inspectable developer-tooling problem:
        IPv4 CIDR arithmetic — parse, network/broadcast, membership, subnets, aggregate. No `ipaddress` dep.

        ## Portfolio Role

        This repository is part of the local-first engineering portfolio around
        agentic AI infrastructure, evaluation, parsing, safety boundaries, and
        small tools that can be understood from a fresh source checkout. It is not
        here to inflate repository count; it should either provide a reusable
        primitive, a benchmark surface, or a concrete local workflow.

        Topics: cidr, ipv4, networking, python, subnet, zero-dependencies

        ## Current Gates

        - Latest completed CI: success
        - Source files counted by audit: 2
        - Test files counted by audit: 4
        - Latest release: not release-tracked yet
        - License: MIT

        ## Upgrade Path

        - Add a local threat model and recovery story for bad input, partial writes, and interrupted runs.
- Add a deterministic demo fixture that creates inspectable output under a temporary directory.
- Document which operations are safe by default and which require user trust.

        ## Reviewer Contract

        A serious reviewer should be able to clone the repository, read the
        README and this brief, run the tests, and understand exactly what is
        claimed. Future work should prefer deeper correctness, better fixtures,
        clearer limits, and stronger local demos over broad feature lists.
