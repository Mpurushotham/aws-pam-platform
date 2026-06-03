# AWS PAM Infrastructure - common task automation
# Usage: make <target>   (run `make help` for the list)

SHELL := /bin/bash
.DEFAULT_GOAL := help

ENV ?= dev
TF_DIR := terraform/environments/$(ENV)
PY_DIR := scripts/python
PYTHON ?= python3

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
.PHONY: setup
setup: ## Install Python deps and pre-commit hooks
	$(PYTHON) -m pip install -r $(PY_DIR)/requirements.txt
	$(PYTHON) -m pip install pre-commit
	pre-commit install

# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------
.PHONY: tf-init
tf-init: ## terraform init for ENV (default: dev)
	cd $(TF_DIR) && terraform init

.PHONY: tf-plan
tf-plan: ## terraform plan for ENV
	cd $(TF_DIR) && terraform plan -out=tfplan

.PHONY: tf-apply
tf-apply: ## terraform apply for ENV
	cd $(TF_DIR) && terraform apply tfplan

.PHONY: tf-destroy
tf-destroy: ## terraform destroy for ENV
	cd $(TF_DIR) && terraform destroy

.PHONY: tf-fmt
tf-fmt: ## Format all Terraform files
	terraform fmt -recursive terraform/

.PHONY: tf-validate
tf-validate: ## Validate Terraform for ENV
	cd $(TF_DIR) && terraform init -backend=false && terraform validate

# ---------------------------------------------------------------------------
# Security / linting
# ---------------------------------------------------------------------------
.PHONY: lint
lint: ## Run tflint + checkov across modules
	tflint --recursive --chdir=terraform || true
	checkov -d terraform --quiet --compact || true

.PHONY: scan
scan: ## Run security scans (checkov + trivy)
	checkov -d terraform --quiet || true
	trivy config terraform/ || true

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
.PHONY: py-fmt
py-fmt: ## Format Python with black + isort
	black $(PY_DIR)
	isort --profile black $(PY_DIR)

.PHONY: py-lint
py-lint: ## Lint Python with flake8 + pylint
	flake8 $(PY_DIR)
	pylint $(PY_DIR)/*.py || true

.PHONY: test
test: ## Run pytest with coverage
	$(PYTHON) -m pytest $(PY_DIR)/tests -v --cov=$(PY_DIR) --cov-report=term-missing

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
.PHONY: ci
ci: tf-fmt tf-validate lint py-lint test ## Run the full local CI gate

.PHONY: clean
clean: ## Remove caches and build artifacts
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '.terraform' -prune -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov reports
