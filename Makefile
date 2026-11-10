.PHONY: help install demo test lint-ready clean docker-build docker-run

help:
	@echo "PQC Readiness Auditor — make targets"
	@echo ""
	@echo "  install        install python dependencies"
	@echo "  demo           run the end-to-end demo"
	@echo "  test           run the test suite"
	@echo "  lint-ready     prepare lint tooling (pip install ruff/black)"
	@echo "  docker-build   build the Docker image"
	@echo "  docker-run     run the dashboard in Docker"
	@echo "  clean          remove local caches and build artifacts"

install:
	python3 -m pip install --break-system-packages -r requirements.txt

demo:
	python3 demo.py

test:
	python3 -m unittest discover -s tests -v

lint-ready:
	python3 -m pip install --break-system-packages ruff black

docker-build:
	docker build -t pqc-auditor .

docker-run: docker-build
	docker run --rm -p 8080:8080 pqc-auditor

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + || true
	find . -type f -name "*.pyc" -delete || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist src/*.egg-info 2>/dev/null || true
