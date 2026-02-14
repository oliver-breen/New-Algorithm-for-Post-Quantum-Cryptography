# Contributing

Thanks for contributing.

## Development Setup

1. Create a virtual environment and install dev tools:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
```

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## Benchmarks

```bash
RUN_BENCHMARKS=1 python -m unittest tests/test_benchmarks.py -v
```

To update the baseline:

```bash
python scripts/generate_benchmark_baseline.py
```

## Lint and Type Checks

```bash
ruff check .
mypy quantaweave
```

## CI Gates

- Lint (ruff)
- Type checking (mypy)
- Unit tests
- Benchmarks with baseline thresholds
