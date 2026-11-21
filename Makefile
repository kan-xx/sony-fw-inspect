PYTHON ?= python3

.PHONY: all test clean

all: test

test:
	@if $(PYTHON) -c "import pytest" >/dev/null 2>&1; then \
		PYTHONPATH=src $(PYTHON) -m pytest -v tests; \
	else \
		PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v; \
	fi

clean:
	rm -rf build dist .pytest_cache src/*.egg-info arm-loader-vm/work *.o
	find . -type d -name "__pycache__" -exec rm -rf {} +
