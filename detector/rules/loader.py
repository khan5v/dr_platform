"""Load Sigma-style YAML rules from a directory."""

from pathlib import Path
import yaml

from detector.rules.sigma_rule import SigmaRule

_REQUIRED_FIELDS = ("title", "id", "detection", "level", "custom")
_REQUIRED_CUSTOM = ("window_seconds", "trigger")


def load_rules(directory: str | Path) -> list[SigmaRule]:
    """Glob *.yml in *directory*, parse each, return SigmaRule instances."""
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"Rule directory not found: {directory}")

    rules = []
    for path in sorted(directory.glob("*.yml")):
        definition = _parse_and_validate(path)
        rules.append(SigmaRule(definition))
    return rules


def load_rule(path: str | Path) -> SigmaRule:
    """Load a single rule file — useful for tests."""
    definition = _parse_and_validate(Path(path))
    return SigmaRule(definition)


def _parse_and_validate(path: Path) -> dict:
    with open(path) as f:
        definition = yaml.safe_load(f)

    for field in _REQUIRED_FIELDS:
        if field not in definition:
            raise ValueError(f"{path.name}: missing required field '{field}'")

    custom = definition["custom"]
    for field in _REQUIRED_CUSTOM:
        if field not in custom:
            raise ValueError(
                f"{path.name}: missing required custom field '{field}'"
            )

    detection = definition["detection"]
    if "selection" not in detection:
        raise ValueError(f"{path.name}: detection must have a 'selection'")
    if "condition" not in detection:
        raise ValueError(f"{path.name}: detection must have a 'condition'")

    return definition
