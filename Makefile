.PHONY: setup test test-fast lint dashboard live diagnose clean

PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt

test-fast:
	$(PYTHON) -B test/test_risk_classifier.py
	$(PYTHON) -B test/test_response_engine.py

test:
	$(PYTHON) -m pytest test -v

lint:
	PYTHONPYCACHEPREFIX=/private/tmp/ids_pycache $(PYTHON) -m py_compile app/*.py clear_events.py test/*.py test/simulations/*.py test/data/fake_data.py

dashboard:
	cd app && ../$(BIN)/streamlit run dashboard.py

live:
	cd app && sudo ../$(BIN)/python live_capture.py

diagnose:
	cd app && sudo ../$(BIN)/python diagnose_features.py --timeout 60 --maxflows 5

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
