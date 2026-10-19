from shadowrun import canary


def test_canaries_and_decoys():
    cs = canary.create_home("test-canary")
    try:
        for kind, rel in canary.CANARY_FILES.items():
            assert cs.tokens[kind] in (cs.home / rel).read_text()
        assert (cs.home / ".gitconfig").exists()
        assert "CANARY" not in (cs.home / ".gitconfig").read_text()
        assert cs.canary_paths["ssh"] == "/home/sandbox/.ssh/id_rsa"
    finally:
        canary.cleanup_home(cs)
