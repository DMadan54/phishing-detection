# engine

The `phishlens` Python package: every check, the scoring and the HTTP API.

- `phishlens/findings.py`: the `Finding` model, the `Check` protocol and the
  `CheckContext` that carries every network service a check may use.
- `phishlens/registry.py`: the one list of checks, and turning them off by name.
- `phishlens/runner.py`: runs checks and turns any crash into a `check_error`
  finding.
- `phishlens/api.py`: the FastAPI app.
- `tests/`: unit tests. They never touch the network; `tests/conftest.py`
  blocks every non-loopback connection. `tests/fixtures/` holds hand-made
  emails that use reserved domains only.

See the root README for how to run it.
