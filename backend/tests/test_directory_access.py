"""How Entra ID app roles and groups become one platform role (docs/entra-id.md)."""

from app.models.directory import MappingKind
from app.models.user import ApprovalLevel, Role
from app.modules.directory import access
from app.modules.directory.access import Rule

APP, GROUP = MappingKind.APP_ROLE, MappingKind.GROUP
NONE, L1, L2, L3 = ApprovalLevel.NONE, ApprovalLevel.L1, ApprovalLevel.L2, ApprovalLevel.L3

RULES = [
    Rule(APP, "AppSec.Analyst", Role.APPSEC, L1, None),
    Rule(APP, "AppSec.Lead", Role.APPSEC, L2, None),
    Rule(APP, "Mgmt.RiskExec", Role.MANAGEMENT, L3, None),
    Rule(GROUP, "11111111-aaaa", Role.DEV_TEAM, NONE, "Team Beta"),
    Rule(GROUP, "22222222-bbbb", Role.DEV_TEAM, NONE, "Team Alpha"),
    Rule(GROUP, "33333333-cccc", Role.ADMIN, NONE, None),
]


def test_nothing_matches_means_no_access():
    assert access.resolve(RULES, ["Something.Else"], ["99999999"]) is None


def test_app_role_match_is_case_insensitive():
    granted = access.resolve(RULES, ["appsec.analyst"], [])
    assert granted and granted.role == Role.APPSEC and granted.approval_level == L1


def test_highest_level_for_the_winning_role():
    granted = access.resolve(RULES, ["AppSec.Analyst", "AppSec.Lead"], [])
    assert granted and granted.approval_level == L2


def test_broadest_role_wins_and_brings_only_its_own_level():
    granted = access.resolve(RULES, ["Mgmt.RiskExec"], ["33333333-cccc"])
    assert granted and granted.role == Role.ADMIN and granted.approval_level == NONE


def test_appsec_beats_management():
    granted = access.resolve(RULES, ["Mgmt.RiskExec", "AppSec.Analyst"], [])
    assert granted and granted.role == Role.APPSEC and granted.approval_level == L1


def test_dev_team_takes_its_team_from_the_group():
    granted = access.resolve(RULES, [], ["11111111-AAAA"])
    assert granted and granted.role == Role.DEV_TEAM and granted.owner_team == "Team Beta"


def test_two_teams_pick_the_first_alphabetically():
    granted = access.resolve(RULES, [], ["11111111-aaaa", "22222222-bbbb"])
    assert granted and granted.owner_team == "Team Alpha"
    assert granted.matched == ("group:11111111-aaaa", "group:22222222-bbbb")


def test_pipeline_can_never_come_from_the_directory():
    rules = [Rule(APP, "CI", Role.PIPELINE, NONE, None)]
    assert access.resolve(rules, ["CI"], []) is None
    assert access.rule_errors(Role.PIPELINE, NONE, None)


def test_rule_validation():
    assert access.rule_errors(Role.DEV_TEAM, NONE, " ")
    assert access.rule_errors(Role.AUDIT, L2, None)
    assert access.rule_errors(Role.APPSEC, L2, None) == []
    assert access.rule_errors(Role.DEV_TEAM, NONE, "Team Alpha") == []
