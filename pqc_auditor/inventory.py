from __future__ import annotations

import json
import typing

from pqc_auditor.schema import MoscaScenario


class InventoryItem(typing.TypedDict, total=False):
    identifier: str
    data_shelf_life_years: float
    migration_time_years: float
    quantum_arrival_scenario: MoscaScenario
    tags: typing.List[str]


class Inventory(typing.TypedDict):
    schema_version: str
    items: typing.List[InventoryItem]


DEFAULT_INVENTORY: Inventory = {
    "schema_version": "1.0.0",
    "items": [],
}


def load_inventory(path: str) -> Inventory:
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        raise ValueError(f"Could not read inventory file {path}: {e}") from e

    if not isinstance(payload.get("items"), list):
        raise ValueError("Inventory JSON must contain a list under 'items'")

    cleaned: typing.List[InventoryItem] = []
    for item in payload["items"]:
        cleaned.append(
            {
                "identifier": item.get("identifier", ""),
                "data_shelf_life_years": float(item.get("data_shelf_life_years", 10.0)),
                "migration_time_years": float(item.get("migration_time_years", 3.0)),
                "quantum_arrival_scenario": item.get("quantum_arrival_scenario", MoscaScenario.MEDIAN),
                "tags": item.get("tags", []),
            }
        )
    return {"schema_version": payload.get("schema_version", "1.0.0"), "items": cleaned}
