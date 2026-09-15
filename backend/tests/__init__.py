"""AegisLab security test modules package."""

from .auth_tests import AuthTests
from .authorization_tests import AuthorizationTests
from .injection_tests import InjectionTests
from .rate_limit_tests import RateLimitTests
from .data_exposure_tests import DataExposureTests
from .transport_security_tests import TransportSecurityTests
from .mass_assignment_tests import MassAssignmentTests
from .ssrf_tests import SsrfTests
from .inventory_tests import InventoryTests

MODULE_REGISTRY = {
    "auth_tests": AuthTests,
    "authorization_tests": AuthorizationTests,
    "injection_tests": InjectionTests,
    "rate_limit_tests": RateLimitTests,
    "data_exposure_tests": DataExposureTests,
    "transport_security_tests": TransportSecurityTests,
    "mass_assignment_tests": MassAssignmentTests,
    "ssrf_tests": SsrfTests,
    "inventory_tests": InventoryTests,
}

__all__ = [
    "AuthTests", "AuthorizationTests", "InjectionTests",
    "RateLimitTests", "DataExposureTests", "TransportSecurityTests",
    "MassAssignmentTests", "SsrfTests", "InventoryTests",
    "MODULE_REGISTRY",
]
