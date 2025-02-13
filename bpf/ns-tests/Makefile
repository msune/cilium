.PHONY: check

PYTHONPATH := $(shell echo $$PYTHONPATH:`pwd`)
PYTEST_OPTS := -s

VENV_NAME := cilium_tests
VENV_PATH := $(HOME)/.$(VENV_NAME)

all: check
check:
	sudo PYTHONPATH=$(PYTHONPATH) $(VENV_PATH)/bin/pytest $(PYTEST_OPTS)

_setup_venv:
	@echo "Creating virtual environment under $(VENV_PATH)"
	@python3 -m venv $(VENV_PATH)
	@echo "Installing dependencies..."
	@$(VENV_PATH)/bin/pip3 install -r requirements.txt
setup: _setup_venv

clean_setup:
	@rm -rf $(VENV_PATH)
clean:
	@sudo rm -rf output/*
