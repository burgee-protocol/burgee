# Contributing

This is the reference implementation of a specification. Two rules follow from that.

1. **The spec leads.** A change that alters what goes on the wire — a beacon byte, a message
   field, an encoding, a timeout — is a BEP in
   [burgee-protocol/spec](https://github.com/burgee-protocol/spec/blob/main/CONTRIBUTING.md) first.
   The pull request here links the BEP and lands after it is Final.
2. **One CLA.** Sign the [Contributor License Agreement](https://github.com/burgee-protocol/spec/blob/main/CLA.md)
   once; it covers every repository in the organization.

Everything else (a bug, a clearer API, a faster path, a new transport, a test) is an
ordinary pull request. Keep the protocol core free of hardware dependencies: anything that
needs a radio goes under `burgee/transport/` behind the `ble` extra.

```sh
pip install -e '.[dev]'
pytest
ruff check src tests && ruff format src tests
```

Registry values are never typed into code. They come from `src/burgee/data/registries.json`,
refreshed with `python tools/sync_registries.py ../spec`; a test fails if the two drift.
