"""YAML loading helpers for repository static assets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

try:
    from scripts.external_json import read_stable_bytes
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import read_stable_bytes


MAX_REPOSITORY_YAML_BYTES = 64 * 1024


class RepositoryYamlError(yaml.YAMLError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: Any, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    value: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            if key in value:
                raise RepositoryYamlError("YAML source is invalid")
            value[key] = loader.construct_object(value_node, deep=deep)
        except TypeError:
            raise RepositoryYamlError("YAML source is invalid") from None
    return value


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def read_stable_yaml_text(
    path: Path, *, max_bytes: int = MAX_REPOSITORY_YAML_BYTES
) -> str:
    return read_stable_bytes(path, max_bytes=max_bytes).decode("utf-8")


def parse_unique_yaml(text: str) -> Any:
    try:
        return yaml.load(text, Loader=_UniqueKeySafeLoader)
    except RepositoryYamlError:
        raise
    except (yaml.YAMLError, RecursionError):
        raise RepositoryYamlError("YAML source is invalid") from None


def parse_unique_yaml_all(text: str) -> list[Any]:
    try:
        return list(yaml.load_all(text, Loader=_UniqueKeySafeLoader))
    except RepositoryYamlError:
        raise
    except (yaml.YAMLError, RecursionError):
        raise RepositoryYamlError("YAML source is invalid") from None


def load_unique_yaml_with_text(
    path: Path, *, max_bytes: int = MAX_REPOSITORY_YAML_BYTES
) -> tuple[Any, str]:
    text = read_stable_yaml_text(path, max_bytes=max_bytes)
    return parse_unique_yaml(text), text


def load_unique_yaml(
    path: Path, *, max_bytes: int = MAX_REPOSITORY_YAML_BYTES
) -> Any:
    return load_unique_yaml_with_text(path, max_bytes=max_bytes)[0]


def load_unique_yaml_all(
    path: Path, *, max_bytes: int = MAX_REPOSITORY_YAML_BYTES
) -> list[Any]:
    return parse_unique_yaml_all(
        read_stable_yaml_text(path, max_bytes=max_bytes)
    )
