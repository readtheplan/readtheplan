"""readtheplan custom exceptions."""


class ReadThePlanError(Exception):
    """Base exception for all readtheplan errors."""
    pass


class PlanError(ValueError, ReadThePlanError):
    """Error parsing or processing a plan file."""
    pass


class OverlayError(ValueError, ReadThePlanError):
    """Error applying an overlay."""
    pass


class CatalogSchemaError(ValueError, ReadThePlanError):
    """Error validating a compliance catalog."""
    pass


class SigningError(ValueError, ReadThePlanError):
    """Error during signing or verification."""
    pass


class MissingMCPDependencyError(RuntimeError, ReadThePlanError):
    """MCP dependencies not installed."""
    pass


class MissingSigningDependencyError(RuntimeError, ReadThePlanError):
    """Signing dependencies not installed."""
    pass
