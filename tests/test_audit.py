import sqlite3

import pytest

from shadowrun import audit, config, db


@pytest.fixture
def tmpdb(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    db.init_db()
    return config.DB_PATH


def test_chain_verifies(tmpdb):
    assert audit.verify() == {"ok": True, "checked": 0, "broken_id": None}
    for i in range(5):
        audit.append("ACTION_RECEIVED", f"r{i}", {"spec": "x", "i": i})
    assert audit.verify() == {"ok": True, "checked": 5, "broken_id": None}


def test_first_entry_links_to_genesis(tmpdb):
    audit.append("FETCHED", "r", {"a": 1})
    assert audit.list_entries()[0]["prev_hash"] == "GENESIS"


def test_payload_tamper_detected(tmpdb):
    for i in range(4):
        audit.append("ACTION_RECEIVED", f"r{i}", {"i": i})
    con = sqlite3.connect(tmpdb)
    con.execute("UPDATE audit_log SET payload_json='{\"i\":99}' WHERE id=2")
    con.commit()
    con.close()
    res = audit.verify()
    assert res["ok"] is False and res["broken_id"] == 2


def test_deleted_middle_row_detected(tmpdb):
    for i in range(4):
        audit.append("ACTION_RECEIVED", f"r{i}", {"i": i})
    con = sqlite3.connect(tmpdb)
    con.execute("DELETE FROM audit_log WHERE id=2")
    con.commit()
    con.close()
    assert audit.verify()["ok"] is False


def test_unknown_event_type_rejected(tmpdb):
    with pytest.raises(ValueError):
        audit.append("BOGUS", None, {})
