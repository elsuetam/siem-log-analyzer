"""Testes unitários para o catálogo de técnicas MITRE ATT&CK."""

from __future__ import annotations

from siem.mitre.attack_reference import (
    ACTIVE_SCANNING,
    BRUTE_FORCE,
    EXPLOIT_PUBLIC_FACING_APPLICATION,
)


def test_brute_force_technique_has_correct_id() -> None:
    """A técnica de Brute Force deve ter o ID T1110."""
    assert BRUTE_FORCE.technique_id == "T1110"
    assert BRUTE_FORCE.name == "Brute Force"


def test_active_scanning_technique_has_correct_id() -> None:
    """A técnica de Active Scanning deve ter o ID T1595."""
    assert ACTIVE_SCANNING.technique_id == "T1595"


def test_exploit_public_facing_application_has_correct_id() -> None:
    """A técnica de Exploit Public-Facing Application deve ter o ID T1190."""
    assert EXPLOIT_PUBLIC_FACING_APPLICATION.technique_id == "T1190"


def test_all_techniques_have_valid_mitre_url() -> None:
    """Todas as técnicas devem apontar para uma URL válida do site oficial MITRE."""
    for technique in (BRUTE_FORCE, ACTIVE_SCANNING, EXPLOIT_PUBLIC_FACING_APPLICATION):
        assert technique.url.startswith("https://attack.mitre.org/techniques/")
        assert technique.technique_id in technique.url