# Release Process

## Versioning

- Update `pyproject.toml` version.
- Update `quantaweave/__init__.py` __version__.
- Add a changelog entry in `CHANGELOG.md`.

## Checks

```bash
ruff check .
mypy quantaweave
python -m unittest discover -s tests -p "test_*.py" -v
RUN_BENCHMARKS=1 BENCHMARK_USE_BASELINE=1 python -m unittest tests/test_benchmarks.py -v
```

## Build

```bash
python -m build
```

## Tag

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
```
