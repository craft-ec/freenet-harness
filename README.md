# freenet-harness

Drives a real Freenet node: deploys contracts, round-trips state, records
timings. Every measured number in `craftworks-docs` comes from here.

    cargo run -- roundtrip --n 3 --size 4096
