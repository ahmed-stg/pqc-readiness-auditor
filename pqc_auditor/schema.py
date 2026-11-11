from __future__ import annotations

import typing
from enum import Enum

SCAN_RESULT_VERSION = "1.0.0"


class FindingStatus(str, Enum):
    OK = "ok"
    WEAK = "weak"
    EXPIRED = "expired"
    ERROR = "error"
    UNREADABLE = "unreadable"


class FindingCategory(str, Enum):
    OK = "ok"
    CLASSICALLY_WEAK = "classically_weak"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    HYBRID_PQC_READY = "hybrid_pqc_ready"


class Finding(typing.TypedDict, total=False):
    file: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    expired: bool
    not_yet_valid: bool
    signature_algorithm: str
    key_type: str
    key_size: int
    findings: typing.List[str]
    category: FindingCategory
    status: FindingStatus
    error: str


class ScanResult(typing.TypedDict):
    version: str
    scanned_at: str
    scanner: str
    findings: typing.List[Finding]


class MoscaScenario(str, Enum):
    OPTIMISTIC = "optimistic"
    MEDIAN = "median"
    CONSERVATIVE = "conservative"


class MoscaAssessment(typing.TypedDict):
    data_shelf_life_years: float
    migration_time_years: float
    quantum_arrival_year: int
    quantum_arrival_scenario: MoscaScenario
    mosca_x: float
    mosca_y: float
    mosca_z: int
    at_risk: bool
    margin_years: float
    risk_ratio: float
    recommendation: str


class ComplianceResult(typing.TypedDict):
    standard: str
    assessed_year: int
    required_year: int
    total_assets: int
    weak_assets: int
    strong_assets: int
    compliance_percentage: float
    badge: str
    timelines: typing.Dict[str, int]


class Assessment(typing.TypedDict):
    version: str
    assessed_at: str
    scan_result_version: str
    overall_score: float
    grade: str
    weak_asset_count: int
    total_assets: int
    mosca: MoscaAssessment
    compliance: ComplianceResult


class CBOMComponent(typing.TypedDict, total=False):
    type: str
    name: str
    version: str
    description: typing.List[str]
    purl: str
    cryptoProperties: typing.Dict[str, typing.Any]


class CBOMMetadata(typing.TypedDict, total=False):
    timestamp: str
    tools: typing.List[typing.Dict[str, str]]
    component: CBOMComponent


class CBOM(typing.TypedDict):
    bomFormat: str
    specVersion: str
    serialNumber: str
    version: int
    metadata: CBOMMetadata
    components: typing.List[CBOMComponent]
