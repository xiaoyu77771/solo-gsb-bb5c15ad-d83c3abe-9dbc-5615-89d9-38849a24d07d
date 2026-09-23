"""API tests for GET /api/v1/audits/{id}/verify (stored-result verification)."""

import json

from app import database

RLO = "‮"
PDF = "‬"
LRM = "‎"


def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def _verify(client, audit_id):
    return client.get(f"/api/v1/audits/{audit_id}/verify")


def _tamper(audit_id, mutate):
    """Mutate the persisted result_json of one record, bypassing the parser."""
    with database.connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
        result = json.loads(row["result_json"])
        mutate(result)
        conn.execute(
            "UPDATE audits SET result_json = ? WHERE id = ?",
            (json.dumps(result, ensure_ascii=False), audit_id),
        )


def _tamper_raw_text(audit_id, text):
    with database.connect() as conn:
        conn.execute(
            "UPDATE audits SET raw_text = ? WHERE id = ?", (text, audit_id)
        )


# ------------------------------------------------------------------ basics ---


def test_verify_missing_record_is_404(client):
    resp = _verify(client, 9999)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_verify_fresh_record_is_consistent(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF, "p.diff").json()["id"]
    body = _verify(client, audit_id).json()

    assert body == {"id": audit_id, "consistent": True,
                    "diff_count": 0, "differences": []}


def test_verify_clean_and_null_fields_are_consistent(client):
    # LRM is reported with scope_end/paired_with = null; a null value must not
    # be confused with an absent field.
    audit_id = _post(client, "a" + LRM + "b").json()["id"]
    body = _verify(client, audit_id).json()
    assert body["consistent"] is True
    assert body["differences"] == []


def test_verify_is_read_only(client):
    audit_id = _post(client, RLO + "end.js").json()["id"]
    before = client.get(f"/api/v1/audits/{audit_id}").json()

    _verify(client, audit_id)
    _verify(client, audit_id)  # repeatable
    after = client.get(f"/api/v1/audits/{audit_id}").json()
    assert after == before


# -------------------------------------------------------------- differences --


def test_verify_detects_changed_scalar_field(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF).json()["id"]

    def change(result):
        result["risk_level"] = "low"  # parser recomputes "high"

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    assert body["diff_count"] == 1
    diff = body["differences"][0]
    assert diff == {
        "path": "/risk_level",
        "stored_value": "low",
        "recomputed_value": "high",
        "stored_present": True,
        "recomputed_present": True,
    }


def test_verify_detects_nested_array_index_field(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF).json()["id"]

    def change(result):
        result["controls"][0]["risk"] = "critical"

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    assert body["diff_count"] == 1
    diff = body["differences"][0]
    assert diff["path"] == "/controls/0/risk"
    assert diff["stored_value"] == "critical"
    assert diff["recomputed_value"] == "high"
    assert diff["stored_present"] is True
    assert diff["recomputed_present"] is True


def test_verify_missing_field_distinct_from_null(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF).json()["id"]

    def change(result):
        del result["controls"][0]["scope_end"]       # absent, not null
        result["controls"][1]["paired_with"] = None  # present, value null

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()
    by_path = {d["path"]: d for d in body["differences"]}

    absent = by_path["/controls/0/scope_end"]
    assert absent["stored_present"] is False
    assert absent["recomputed_present"] is True
    assert absent["stored_value"] is None
    assert absent["recomputed_value"] == 10  # RLO at index 1, PDF at index 10

    nulled = by_path["/controls/1/paired_with"]
    assert nulled["stored_present"] is True
    assert nulled["recomputed_present"] is True
    assert nulled["stored_value"] is None
    assert nulled["recomputed_value"] == "U+202E"


def test_verify_extra_stored_key_is_recomputed_missing(client):
    audit_id = _post(client, "clean").json()["id"]

    def change(result):
        result["extra_note"] = "tampered"

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    assert body["diff_count"] == 1
    diff = body["differences"][0]
    assert diff["path"] == "/extra_note"
    assert diff["stored_value"] == "tampered"
    assert diff["recomputed_value"] is None
    assert diff["stored_present"] is True
    assert diff["recomputed_present"] is False


def test_verify_array_shrink_reports_whole_item_at_index(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF).json()["id"]

    def change(result):
        result["controls"].pop()  # drop the PDF element

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    assert body["diff_count"] == 1
    diff = body["differences"][0]
    assert diff["path"] == "/controls/1"
    assert diff["stored_present"] is False
    assert diff["recomputed_present"] is True
    assert diff["stored_value"] is None
    assert diff["recomputed_value"]["abbreviation"] == "PDF"


def test_verify_differences_sorted_by_json_pointer(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF).json()["id"]

    def change(result):
        result["controls"][1]["logical_index"] = 99
        result["controls"][0]["risk"] = "info"
        result["risk_level"] = "info"

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    # numeric array indices order 0 before 1; "/controls..." precedes "/risk..."
    assert [d["path"] for d in body["differences"]] == [
        "/controls/0/risk",
        "/controls/1/logical_index",
        "/risk_level",
    ]
    assert body["diff_count"] == 3


def test_verify_numeric_indices_sort_numerically(client):
    audit_id = _post(client, RLO + "x" + PDF).json()["id"]

    def change(result):
        # Fabricate nine extra controls; indices 2..10 exist only in stored.
        result["controls"].extend({"abbreviation": "X"} for _ in range(9))

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()
    paths = [d["path"] for d in body["differences"]]

    # Numerical ordering: /controls/10 must come last, not before /controls/2.
    assert paths == [f"/controls/{i}" for i in range(2, 11)]


def test_verify_bool_is_not_number(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF).json()["id"]

    def change(result):
        result["controls"][0]["is_orphan"] = 0  # JSON number, not false

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    assert body["diff_count"] == 1
    diff = body["differences"][0]
    assert diff["path"] == "/controls/0/is_orphan"
    assert diff["stored_value"] == 0
    assert diff["recomputed_value"] is False


def test_verify_pointer_escapes_slash_in_key(client):
    audit_id = _post(client, "clean").json()["id"]

    def change(result):
        result["weird/key"] = 1

    _tamper(audit_id, change)
    body = _verify(client, audit_id).json()

    assert body["differences"][0]["path"] == "/weird~1key"


def test_verify_recomputes_from_stored_raw_text(client):
    audit_id = _post(client, "clean").json()["id"]
    _tamper_raw_text(audit_id, "x" + RLO + "evil.exe" + PDF)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    paths = {d["path"] for d in body["differences"]}
    assert "/risk_level" in paths
    assert "/length" in paths
