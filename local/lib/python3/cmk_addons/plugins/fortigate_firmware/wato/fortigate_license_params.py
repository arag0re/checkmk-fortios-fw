# fortigate_license_params.py
from cmk.gui.i18n import _
from cmk.gui.valuespec import (
    Dictionary, Integer, TextAscii, ListOf, Alternative, DropdownChoice, RegExpUnicode
)
from cmk.gui.plugins.wato import (
    rulespec_registry, CheckParameterRulespecWithoutItem, RulespecGroupCheckParametersApplications
)

def _severity_choice(title):
    return DropdownChoice(
        title=title,
        choices=[("OK", "OK"), ("WARN", "WARN"), ("CRIT", "CRIT"), ("UNKNOWN", "UNKNOWN")],
        default_value="WARN",
    )

def _valuespec_fortigate_license_params():
    return Dictionary(
        title=_("FortiGate Licenses"),
        elements=[
            ("status_severity",
             Dictionary(
                 title=_("Severity by license status (defaults)"),
                 elements=[
                     ("licensed", _severity_choice(_("Licensed"))),
                     ("free_license", _severity_choice(_("Free license"))),
                     ("no_license", _severity_choice(_("No license"))),
                     ("unavailable", _severity_choice(_("Unavailable"))),
                     ("other", _severity_choice(_("Other/unknown"))),
                 ],
                 optional_keys=[],
                 default_value={
                     "licensed": "OK",
                     "free_license": "WARN",
                     "no_license": "CRIT",
                     "unavailable": "WARN",
                     "other": "WARN",
                 },
             )),
            ("expiry",
             Dictionary(
                 title=_("Expiration thresholds"),
                 elements=[
                     ("warn_days", Integer(title=_("WARN at days to expiry ≤"), default_value=14, minvalue=0)),
                     ("crit_days", Integer(title=_("CRIT at days to expiry ≤"), default_value=3, minvalue=0)),
                     ("warn_severity", _severity_choice(_("Severity when in WARN window"))),
                     ("crit_severity", _severity_choice(_("Severity when in CRIT window"))),
                     ("expired_severity", _severity_choice(_("Severity when expired"))),
                 ],
                 optional_keys=[],
                 default_value={"warn_days": 14, "crit_days": 3, "warn_severity": "WARN", "crit_severity": "CRIT", "expired_severity": "CRIT"},
             )),
            ("fortiguard_connectivity",
             Dictionary(
                 title=_("FortiGuard connectivity issue severity"),
                 elements=[
                     ("issue_severity", _severity_choice(_("Severity when connectivity issue detected"))),
                 ],
                 optional_keys=[],
                 default_value={"issue_severity": "WARN"},
             )),
            ("ignore_modules",
             ListOf(
                 valuespec=TextAscii(title=_("Module name (exact)")),
                 title=_("Globally ignore these modules"),
                 default_value=[],
             )),
            ("overrides",
             ListOf(
                 valuespec=Dictionary(
                     title=_("Per-module override"),
                     elements=[
                         ("match",
                          Alternative(
                              title=_("Match module"),
                              elements=[
                                  TextAscii(title=_("Exact module name")),
                                  RegExpUnicode(title=_("Regex (Python)"), allow_empty=False),
                              ],
                              default_value="",
                          )),
                         ("match_type",
                          DropdownChoice(
                              title=_("Match type"),
                              choices=[("exact", _("Exact")), ("regex", _("Regex"))],
                              default_value="exact",
                          )),
                         ("ignore",
                          DropdownChoice(
                              title=_("Ignore this module"),
                              choices=[(False, _("No")), (True, _("Yes"))],
                              default_value=False,
                          )),
                         ("status_severity",
                          Dictionary(
                              title=_("Severity by license status (override)"),
                              elements=[
                                  ("licensed", _severity_choice(_("Licensed"))),
                                  ("free_license", _severity_choice(_("Free license"))),
                                  ("no_license", _severity_choice(_("No license"))),
                                  ("unavailable", _severity_choice(_("Unavailable"))),
                                  ("other", _severity_choice(_("Other/unknown"))),
                              ],
                              optional_keys=["licensed", "free_license", "no_license", "unavailable", "other"],
                          )),
                         ("expiry",
                          Dictionary(
                              title=_("Expiration thresholds (override)"),
                              elements=[
                                  ("warn_days", Integer(title=_("WARN at days to expiry ≤"), minvalue=0)),
                                  ("crit_days", Integer(title=_("CRIT at days to expiry ≤"), minvalue=0)),
                                  ("warn_severity", _severity_choice(_("Severity when in WARN window"))),
                                  ("crit_severity", _severity_choice(_("Severity when in CRIT window"))),
                                  ("expired_severity", _severity_choice(_("Severity when expired"))),
                              ],
                              optional_keys=["warn_days", "crit_days", "warn_severity", "crit_severity", "expired_severity"],
                          )),
                     ],
                 ),
                 title=_("Per-module overrides"),
                 add_label=_("Add override"),
                 allow_empty=True,
                 default_value=[],
             )),
        ],
        optional_keys=["overrides", "ignore_modules"],
    )

rulespec_registry.register(
    CheckParameterRulespecWithoutItem(
        check_group_name="fortigate_license",  # used as ruleset name
        group=RulespecGroupCheckParametersApplications,
        match_type="dict",
        valuespec=_valuespec_fortigate_license_params,
    )
)