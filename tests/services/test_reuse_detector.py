import hashlib
import hmac

from password_bot.services.reuse_detector import ReuseDetector, compute_password_hmac


def _hmac(key: bytes, plaintext: str) -> str:
    return hmac.new(key, plaintext.encode(), hashlib.sha256).hexdigest()


def test_compute_password_hmac_matches_reference():
    key = b"\x01" * 32
    assert compute_password_hmac("pw", key) == _hmac(key, "pw")


def test_detector_finds_cluster():
    key = b"\x02" * 32
    d = ReuseDetector(key)
    d.add("a1", "GitHub", "shared")
    d.add("a2", "GitLab", "shared")
    d.add("a3", "Twitter", "other")
    cluster = d.cluster_for("shared")
    assert {(a_id, name) for a_id, name in cluster} == {("a1", "GitHub"), ("a2", "GitLab")}


def test_detector_removes_account():
    key = b"\x02" * 32
    d = ReuseDetector(key)
    d.add("a1", "GitHub", "shared")
    d.add("a2", "GitLab", "shared")
    d.remove("a1")
    assert {a_id for a_id, _ in d.cluster_for("shared")} == {"a2"}


def test_detector_all_clusters():
    key = b"\x02" * 32
    d = ReuseDetector(key)
    d.add("a1", "GitHub", "shared")
    d.add("a2", "GitLab", "shared")
    d.add("a3", "Twitter", "unique")
    clusters = d.all_clusters(min_size=2)
    assert len(clusters) == 1
    assert {a_id for a_id, _ in clusters[0]} == {"a1", "a2"}
