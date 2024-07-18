BASE := $(shell /bin/pwd)
CODE_COVERAGE = 72
PIPENV ?= pipenv

install:
	$(info [*] Installing pipenv)
	@pip install --upgrade pip
	@pip install pipenv --upgrade
	$(MAKE) dev

dev:
	$(info [*] Installing pipenv project dependencies)
	@$(PIPENV) install
	@$(PIPENV) install -d

lint: ##=> Run Linter
	pipenv run pylint **/**.py

test: ##=> Run pytest
	@POWERTOOLS_TRACE_DISABLED=1 POWERTOOLS_METRICS_NAMESPACE="$(notdir $(shell pwd))" $(PIPENV) run python -m pytest --junitxml=junit/test-results.xml --cov src --cov-report=xml --cov-report=html --cov-report=term-missing --cov-fail-under $(CODE_COVERAGE) tests -vv
