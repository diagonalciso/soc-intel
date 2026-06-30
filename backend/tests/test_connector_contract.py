"""
Contract test across *every* built-in connector.

No network, no live stack: just import each module under
app.connectors.builtin, find its BaseConnector subclass, instantiate it
(connectors carry their own ConnectorConfig, so they take no args), and assert
the config + run() interface the scheduler and SDK rely on.

This is the regression net the project's CLAUDE.md previously claimed but never
had: a malformed config, a bad connector_type, a duplicate name, or a connector
that stops being a coroutine all fail here instead of silently at runtime.
"""
import importlib
import inspect
import pkgutil

import pytest

import app.connectors.builtin as builtin_pkg
from app.connectors.sdk.base import BaseConnector, ConnectorConfig

VALID_TYPES = {"import_external", "enrichment", "stream", "export"}


def _discover():
    """Yield (label, connector_class) for every BaseConnector subclass defined
    in a module directly under app.connectors.builtin."""
    found = []
    for modinfo in pkgutil.iter_modules(builtin_pkg.__path__):
        mod = importlib.import_module(f"app.connectors.builtin.{modinfo.name}")
        for _, cls in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(cls, BaseConnector)
                and cls is not BaseConnector
                and cls.__module__ == mod.__name__
            ):
                found.append((f"{modinfo.name}.{cls.__name__}", cls))
    return found


CONNECTORS = _discover()
IDS = [label for label, _ in CONNECTORS]
CLASSES = [cls for _, cls in CONNECTORS]


def test_discovery_found_connectors():
    # guard against the discovery silently matching nothing (which would make
    # every parametrized test below vacuously pass)
    assert len(CONNECTORS) >= 40, f"only discovered {len(CONNECTORS)} connectors"


@pytest.mark.parametrize("cls", CLASSES, ids=IDS)
def test_instantiates_with_valid_config(cls):
    conn = cls()
    cfg = conn.config
    assert isinstance(cfg, ConnectorConfig)
    assert isinstance(cfg.name, str) and cfg.name.strip(), "name must be non-empty"
    assert cfg.connector_type in VALID_TYPES, f"bad type {cfg.connector_type!r}"
    assert 0 <= cfg.source_reliability <= 100, cfg.source_reliability
    assert cfg.default_tlp.startswith("TLP:"), cfg.default_tlp


@pytest.mark.parametrize("cls", CLASSES, ids=IDS)
def test_run_is_coroutine(cls):
    assert inspect.iscoroutinefunction(cls.run), f"{cls.__name__}.run must be async"


def test_connector_names_are_unique():
    names = [cls().config.name for cls in CLASSES]
    dupes = {n for n in names if names.count(n) > 1}
    assert not dupes, f"duplicate connector names: {dupes}"
