#!/bin/sh
set -eu
cd /work
python -m pip install --no-index --no-build-isolation --find-links=/input/deps --target=/work/site "/input/$ZOLI_ARTIFACT"
PYTHONPATH=/work/site python -c 'import importlib, pathlib; root=pathlib.Path("/work/site"); modules=[p.name for p in root.iterdir() if p.is_dir() and (p/"__init__.py").exists()]; modules += [p.stem for p in root.glob("*.py")]; [importlib.import_module(name) for name in modules if name.isidentifier()]'
