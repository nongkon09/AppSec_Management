from datetime import UTC, date, datetime

from app.models.finding import FindingStatus, SeverityTier
from app.models.user import Role

URL = "/api/v1/reports/executive-summary"


def _dated(db_session, finding, *, detected, fixed=None, sla_start=None):
    finding.first_detected_at = detected
    finding.fixed_at = fixed
    if fixed is not None:
        finding.status = FindingStatus.FIXED
    if sla_start is not None:
        finding.sla_started_on = sla_start
    db_session.commit()
    return finding


def test_monthly_figures_count_issues(
    client, db_session, make_user, auth_headers, make_application, make_version, make_finding
):
    make_user("mgmt.exec", Role.MANAGEMENT)
    version = make_version(make_application(app_name="Retail", owner_team="Team Alpha"))

    # New in August, still open and overdue at the end of August.
    _dated(
        db_session,
        make_finding(version, cve_id="CVE-2026-0001", due_date=date(2026, 8, 20)),
        detected=datetime(2026, 8, 3, tzinfo=UTC),
    )
    # Found in July, fixed in August before its due date.
    _dated(
        db_session,
        make_finding(
            version,
            cve_id="CVE-2026-0002",
            severity_tier=SeverityTier.HIGH,
            kev_flag=False,
            due_date=date(2026, 8, 30),
        ),
        detected=datetime(2026, 7, 10, tzinfo=UTC),
        fixed=datetime(2026, 8, 15, tzinfo=UTC),
        sla_start=date(2026, 7, 10),
    )

    body = client.get(URL, headers=auth_headers("mgmt.exec"), params={"month": "2026-08"}).json()
    current = body["current"]
    assert current["month"] == "2026-08"
    assert current["new"] == 1
    assert current["fixed"] == 1
    assert current["fixed_on_time"] == 1
    assert current["on_time_percent"] == 100.0
    assert current["median_days_to_fix"] == 36.0
    assert current["open_at_end"] == 1
    assert current["overdue_at_end"] == 1

    # At the end of July only the July finding was open.
    assert body["previous"]["open_at_end"] == 1
    assert body["previous"]["new"] == 1
    assert len(body["trend"]) == 6
    assert body["trend"][-1]["month"] == "2026-08"

    assert body["kev_open_at_end"] == 1
    assert body["top_risks"][0]["label"] == "CVE-2026-0001"
    assert body["top_risks"][0]["days_overdue"] == 11
    assert body["applications"][0]["application_name"] == "Retail"
    assert body["scope_team"] is None
    assert body["is_partial"] is False
    assert body["as_of"] == "2026-08-31"


def test_dev_team_sees_only_their_team(
    client, db_session, make_user, auth_headers, make_application, make_version, make_finding
):
    make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
    for team, cve in (("Team Alpha", "CVE-2026-1000"), ("Team Beta", "CVE-2026-2000")):
        version = make_version(make_application(app_name=f"App {team}", owner_team=team))
        _dated(
            db_session,
            make_finding(version, cve_id=cve),
            detected=datetime(2026, 8, 3, tzinfo=UTC),
        )

    body = client.get(URL, headers=auth_headers("dev.alpha"), params={"month": "2026-08"}).json()
    assert body["scope_team"] == "Team Alpha"
    assert body["current"]["new"] == 1
    assert [r["label"] for r in body["top_risks"]] == ["CVE-2026-1000"]


def test_suppressed_findings_are_ignored(
    client, db_session, make_user, auth_headers, make_application, make_version, make_finding
):
    make_user("mgmt.exec", Role.MANAGEMENT)
    version = make_version(make_application())
    _dated(
        db_session,
        make_finding(version, status=FindingStatus.SUPPRESSED),
        detected=datetime(2026, 8, 3, tzinfo=UTC),
    )
    body = client.get(URL, headers=auth_headers("mgmt.exec"), params={"month": "2026-08"}).json()
    assert body["current"]["new"] == 0
    assert body["current"]["open_at_end"] == 0


def test_month_validation_and_access(client, make_user, auth_headers):
    make_user("mgmt.exec", Role.MANAGEMENT)
    make_user("legal.officer", Role.LEGAL)
    headers = auth_headers("mgmt.exec")
    assert client.get(URL, headers=headers, params={"month": "2026-8"}).status_code == 422
    assert client.get(URL, headers=headers, params={"month": "2999-01"}).status_code == 422
    assert client.get(URL, headers=headers, params={"month": "2026-13"}).status_code == 422
    assert (
        client.get(
            URL, headers=auth_headers("legal.officer"), params={"month": "2026-08"}
        ).status_code
        == 403
    )


def test_month_in_progress_is_read_as_of_today(
    db_session, make_user, make_application, make_version, make_finding
):
    """Mid-month, "overdue" means overdue today, not by the end of the month."""
    from app.core.deps import CurrentUser
    from app.modules.reports.service import executive_summary

    version = make_version(make_application())
    _dated(
        db_session,
        make_finding(version, due_date=date(2026, 9, 29)),
        detected=datetime(2026, 9, 1, tzinfo=UTC),
    )
    reader = CurrentUser(username="mgmt.exec", role=Role.MANAGEMENT, owner_team=None)
    now = datetime(2026, 9, 28, 12, tzinfo=UTC)
    report = executive_summary(db_session, reader, 2026, 9, now=now)
    assert report.is_partial is True
    assert report.as_of == date(2026, 9, 28)
    assert report.current.open_at_end == 1
    assert report.current.overdue_at_end == 0
