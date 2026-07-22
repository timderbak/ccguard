"""Threat-intel source monitors (Rule Discovery Agent · E3)."""
from ccguard.server.services.source_monitors.base import (
    SourceItem,
    SourceMonitor,
)

__all__ = ["SourceItem", "SourceMonitor", "default_monitors"]


def default_monitors() -> list[SourceMonitor]:
    """The production set of threat-intel source monitors.

    Single source of truth shared by the scheduled daily sweep
    (``server/main.py``) and the manual "run discovery now" admin trigger, so
    the two never drift. Lazy imports keep package import cheap and cycle-free.
    """
    from ccguard.server.services.source_monitors.atlas import AtlasMonitor
    from ccguard.server.services.source_monitors.atomic_red_team import (
        AtomicRedTeamMonitor,
    )
    from ccguard.server.services.source_monitors.cve_ai_filter import (
        CVEAIFilterMonitor,
    )
    from ccguard.server.services.source_monitors.gitleaks_config import (
        GitleaksConfigMonitor,
    )
    from ccguard.server.services.source_monitors.lakera_blog import LakeraBlogMonitor
    from ccguard.server.services.source_monitors.mitre_attack import MitreAttackMonitor
    from ccguard.server.services.source_monitors.sigma_linux import SigmaLinuxMonitor

    return [
        AtomicRedTeamMonitor(),
        MitreAttackMonitor(),
        AtlasMonitor(),
        LakeraBlogMonitor(),
        CVEAIFilterMonitor(),
        SigmaLinuxMonitor(),
        GitleaksConfigMonitor(),
    ]
