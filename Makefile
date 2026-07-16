.PHONY: install install-dev test lint typecheck clean build docker-run format check all release

PACKAGE = osintdepintel
PYTHON = python3

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"
	$(PYTHON) -m pre-commit install

test:
	$(PYTHON) -m pytest --cov=$(PACKAGE) --cov-report=term-missing --cov-report=html

lint:
	ruff check $(PACKAGE) tests

typecheck:
	mypy $(PACKAGE)

format:
	ruff format $(PACKAGE) tests

build:
	$(PYTHON) -m build

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/ reports/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

docker-build:
	docker compose build

docker-run:
	docker compose run --rm osintdepintel

check: lint typecheck test

all: install-dev check

release:
	@V=$$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/'); \
	NEW=$$(echo "$$V" | awk -F. '{print $$1"."$$2"."$$3+1}'); \
	echo "Releasing v$$NEW..."; \
	sed -i "s/version = \"$$V\"/version = \"$$NEW\"/" pyproject.toml; \
	$(PYTHON) -m build; \
	git add pyproject.toml; \
	git commit -m "release: v$$NEW"; \
	git tag "v$$NEW"; \
	echo "Tagged v$$NEW. Push with: git push --tags origin main"
