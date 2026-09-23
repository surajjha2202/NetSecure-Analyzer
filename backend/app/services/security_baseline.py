from __future__ import annotations

from typing import Any


def build_security_baseline(
    parsed_configuration: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert vendor-specific parser output into the
    vendor-neutral Security Baseline Model.
    """

    vendor = parsed_configuration.get(
        "vendor",
        "Unknown",
    )

    security_parameters = parsed_configuration.get(
        "security_parameters",
        {},
    )

    baseline = {
        "vendor": vendor,
        "management": {},
        "authentication": {},
        "remote_access": {},
        "crypto": {},
        "logging": {},
        "access_control": {},
        "firewall": {},
        "interfaces": {},
        "routing": {},
        "monitoring": {},
    }

    # =========================================================
    # MANAGEMENT
    # =========================================================

    management = security_parameters.get(
        "management",
        {},
    )

    baseline["management"] = {
        "hostname": management.get(
            "hostname"
        ),
        "enable_secret": management.get(
            "enable_secret",
            None,
        ),
        "local_users": management.get(
            "local_users",
            [],
        ),
    }

    # =========================================================
    # AUTHENTICATION
    # =========================================================

    authentication = security_parameters.get(
        "authentication",
        {},
    )

    baseline["authentication"] = {
        "aaa_new_model": authentication.get(
            "aaa_new_model",
            None,
        ),
        "local_users": authentication.get(
            "local_users",
            management.get(
                "local_users",
                [],
            ),
        ),
    }

    # =========================================================
    # CRYPTO
    # =========================================================

    crypto = security_parameters.get(
        "crypto",
        {},
    )

    baseline["crypto"] = {
        "password_encryption": crypto.get(
            "password_encryption",
            None,
        ),
    }

    # =========================================================
    # LOGGING
    # =========================================================

    logging = security_parameters.get(
        "logging",
        {},
    )

    # =========================================================
    # LOCAL BUFFERED LOGGING APPLICABILITY
    # =========================================================
    #
    # NET-003/CIS-LOG-001 currently uses Cisco IOS
    # "logging buffered" semantics.
    #
    # If the parser explicitly detected the parameter, preserve
    # its boolean value.
    #
    # If the parameter was not detected:
    #   - Cisco => False because Cisco supports the control and
    #              its absence means it is not configured.
    #   - Other/unknown vendors => None so the compliance engine
    #              can correctly return NOT_APPLICABLE until
    #              vendor-specific support is implemented or a
    #              learned mapping supplies the parameter.
    #

    if "local_buffered_logging" in logging:
        local_buffered_logging = logging[
            "local_buffered_logging"
        ]
    else:
        local_buffered_logging = None

    baseline["logging"] = {
        "local_buffered_logging": local_buffered_logging,
        "remote_syslog": logging.get(
            "remote_syslog",
            None,
        ),
        "timestamps": logging.get(
            "timestamps",
            None,
        ),
    }

    # =========================================================
    # REMOTE ACCESS
    # =========================================================

    remote_access = security_parameters.get(
        "remote_access",
        {},
    )

    baseline["remote_access"] = {
        "ssh_enabled": remote_access.get(
            "ssh_enabled",
            None,
        ),
        "ssh_version": remote_access.get(
            "ssh_version",
            None,
        ),
        "telnet_enabled": remote_access.get(
            "telnet_enabled",
            None,
        ),
    }

    # =========================================================
    # ACCESS CONTROL
    # =========================================================

    access_control = security_parameters.get(
        "access_control",
        {},
    )

    baseline["access_control"] = {
        "standard_acls": access_control.get(
            "standard_acls",
            0,
        ),
        "extended_acls": access_control.get(
            "extended_acls",
            0,
        ),
    }

    # =========================================================
    # FIREWALL
    # =========================================================

    firewall = security_parameters.get(
        "firewall",
        {},
    )

    baseline["firewall"] = {
        "configured": bool(firewall),
    }

    # =========================================================
    # INTERFACES
    # =========================================================

    interfaces = security_parameters.get(
        "interfaces",
        {},
    )

    baseline["interfaces"] = {
        "count": interfaces.get(
            "count",
            0,
        ),
        "names": interfaces.get(
            "names",
            [],
        ),
    }

    # =========================================================
    # ROUTING
    # =========================================================

    routing = security_parameters.get(
        "routing",
        {},
    )

    baseline["routing"] = {
        "ospf": routing.get(
            "ospf",
            False,
        ),
        "bgp": routing.get(
            "bgp",
            False,
        ),
        "eigrp": routing.get(
            "eigrp",
            False,
        ),
        "isis": routing.get(
            "isis",
            False,
        ),
    }

    # =========================================================
    # MONITORING
    # =========================================================

    logging_values = [
        baseline["logging"]["local_buffered_logging"],
        baseline["logging"]["remote_syslog"],
        baseline["logging"]["timestamps"],
    ]

    if any(value is True for value in logging_values):
        logging_configured = True
    elif all(value is False for value in logging_values):
        logging_configured = False
    else:
        logging_configured = None

    baseline["monitoring"] = {
        "logging_configured": logging_configured,
    }

    return baseline