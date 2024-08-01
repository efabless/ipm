all: dist
.PHONY: dist
dist: veryclean venv/manifest.txt
	./venv/bin/poetry build

.PHONY: lint
lint: venv/manifest.txt
	./venv/bin/black --check .
	./venv/bin/flake8 .

venv: venv/manifest.txt
venv/manifest.txt: ./pyproject.toml
	rm -rf venv
	python3 -m venv ./venv
	PYTHONPATH= ./venv/bin/python3 -m pip install --upgrade pip
	PYTHONPATH= ./venv/bin/python3 -m pip install --upgrade wheel poetry poetry-plugin-export
	PYTHONPATH= ./venv/bin/poetry export --with dev --without-hashes --format=requirements.txt --output=requirements_tmp.txt
	PYTHONPATH= ./venv/bin/python3 -m pip install --upgrade -r requirements_tmp.txt
	PYTHONPATH= ./venv/bin/python3 -m pip freeze > $@
	@echo ">> Venv prepared."

.PHONY: veryclean
veryclean: clean
veryclean:
	rm -rf venv/

.PHONY: update_package
update_package: dist
	python3 -m twine upload dist/* 

.PHONY: clean
clean:
	rm -rf build/
	rm -rf logs/
	rm -rf dist/
	rm -rf *.egg-info
