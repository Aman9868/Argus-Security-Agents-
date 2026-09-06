.PHONY: test run lint clean

test:
	pytest tests/ -v

run:
	uvicorn apps.api.main:app --host 127.0.0.1 --port 8001 --reload

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

