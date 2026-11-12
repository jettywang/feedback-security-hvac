import pytest

from hvac import exceptions
from hvac.kv_rotation import (
    AuditRecord,
    KeyState,
    RotationConflictError,
    RotationStateError,
    rotate_secret,
)


class FakeKvV2:
    """In-memory KV v2 double with Vault-like CAS semantics.

    Simulated server rules:
    * cas=0 succeeds only when the key does not exist.
    * cas=N succeeds only when N is the current version and that version has
      not been destroyed.
    * Anything else is rejected with InvalidRequest, as Vault does.
    """

    def __init__(self):
        self._keys = {}
        self.read_count = 0
        self.write_count = 0

    def seed(self, path, data, version=1, deletion_time="", destroyed=False):
        self._keys[path] = {
            "version": version,
            "data": data,
            "deletion_time": deletion_time,
            "destroyed": destroyed,
        }

    def read_secret_version(self, path, version=None, mount_point="secret",
                            raise_on_deleted_version=True):
        self.read_count += 1
        key = self._keys.get(path)
        if key is None:
            raise exceptions.InvalidPath(f"no value found at {path}")
        metadata = {
            "version": key["version"],
            "deletion_time": key["deletion_time"],
            "destroyed": key["destroyed"],
        }
        if key["destroyed"] or key["deletion_time"]:
            return {"data": {"data": None, "metadata": metadata}}
        return {"data": {"data": dict(key["data"]), "metadata": metadata}}

    def create_or_update_secret(self, path, secret, cas=None, mount_point="secret"):
        self.write_count += 1
        key = self._keys.get(path)
        if key is None:
            if cas != 0:
                raise exceptions.InvalidRequest(
                    "check-and-set parameter did not match the current version"
                )
            self._keys[path] = {
                "version": 1, "data": dict(secret),
                "deletion_time": "", "destroyed": False,
            }
            return {"data": {"version": 1}}
        if cas != key["version"]:
            raise exceptions.InvalidRequest(
                "check-and-set parameter did not match the current version"
            )
        if key["destroyed"]:
            raise exceptions.InvalidRequest(
                f"version {cas} of {path} has been destroyed"
            )
        key["version"] += 1
        key["data"] = dict(secret)
        key["deletion_time"] = ""
        return {"data": {"version": key["version"]}}

    def delete_latest_version_of_secret(self, path, mount_point="secret"):
        self._keys[path]["deletion_time"] = "2026-11-12T00:00:00Z"

    def destroy(self, path):
        self._keys[path]["destroyed"] = True
        self._keys[path]["data"] = None


@pytest.fixture
def kv():
    return FakeKvV2()


@pytest.fixture
def records():
    return []


def audit_into(records):
    return records.append


class TestRotateSecret:
    def test_successful_rotation(self, kv, records):
        kv.seed("app/api-key", {"token": "old"}, version=3)

        result = rotate_secret(
            kv, "app/api-key",
            lambda current: {"token": current["token"] + "-rotated"},
            audit=records.append,
        )

        assert result["data"]["version"] == 4
        assert kv.read_secret_version("app/api-key")["data"]["data"] == {
            "token": "old-rotated"
        }
        assert records == []

    def test_concurrent_write_conflict_loses_race(self, kv, records):
        """Two jobs read version 3; the first write wins, the second must not
        overwrite it."""
        kv.seed("app/api-key", {"token": "v3"}, version=3)

        def competing_job_writes_first(current):
            # While this job rotates, the other job writes its own value.
            kv.create_or_update_secret("app/api-key", {"token": "other-job"}, cas=3)
            return {"token": "my-job"}

        with pytest.raises(RotationConflictError) as exc_info:
            rotate_secret(
                kv, "app/api-key", competing_job_writes_first,
                audit=records.append,
            )

        conflict = exc_info.value
        assert conflict.path == "app/api-key"
        assert conflict.version == 3
        assert "check-and-set" in conflict.reason
        # The winning job's value is untouched.
        assert kv.read_secret_version("app/api-key")["data"]["data"] == {
            "token": "other-job"
        }
        # No automatic re-read/retry: exactly one read and one failed write.
        assert kv.read_count == 2  # one by rotate_secret, one by the assert above
        assert kv.write_count == 2  # winning write + rejected write
        assert records == [
            AuditRecord(
                path="app/api-key",
                version=3,
                reason="check-and-set parameter did not match the current version",
            )
        ]

    def test_soft_delete_after_read_conflicts(self, kv, records):
        """Read v3, then another actor soft-deletes and rewrites the key."""
        kv.seed("app/api-key", {"token": "v3"}, version=3)

        def deleter_acts_first(current):
            kv.delete_latest_version_of_secret("app/api-key")
            kv.create_or_update_secret("app/api-key", {"token": "recovered"}, cas=3)
            return {"token": "my-job"}

        with pytest.raises(RotationConflictError) as exc_info:
            rotate_secret(kv, "app/api-key", deleter_acts_first, audit=records.append)

        assert exc_info.value.version == 3
        assert kv.read_secret_version("app/api-key")["data"]["data"] == {
            "token": "recovered"
        }
        assert len(records) == 1
        assert records[0].path == "app/api-key"
        assert records[0].version == 3

    def test_destroy_after_read_conflicts(self, kv, records):
        """Read v3, then another actor destroys that version."""
        kv.seed("app/api-key", {"token": "v3"}, version=3)

        def destroyer_acts_first(current):
            kv.destroy("app/api-key")
            return {"token": "my-job"}

        with pytest.raises(RotationConflictError) as exc_info:
            rotate_secret(kv, "app/api-key", destroyer_acts_first, audit=records.append)

        assert exc_info.value.path == "app/api-key"
        assert exc_info.value.version == 3
        assert "destroyed" in exc_info.value.reason
        assert records[0].reason == exc_info.value.reason

    @pytest.mark.parametrize(
        "seed_kwargs,expected_state",
        [
            ({"deletion_time": "2026-11-12T00:00:00Z"}, KeyState.SOFT_DELETED),
            ({"destroyed": True}, KeyState.DESTROYED),
        ],
    )
    def test_deleted_or_destroyed_keys_rejected_by_default(
        self, kv, records, seed_kwargs, expected_state
    ):
        kv.seed("app/api-key", {"token": "v2"}, version=2, **seed_kwargs)

        with pytest.raises(RotationStateError) as exc_info:
            rotate_secret(kv, "app/api-key", lambda c: {"token": "new"},
                          audit=records.append)

        assert exc_info.value.state is expected_state
        assert exc_info.value.version == 2
        assert kv.write_count == 0  # no write attempted
        assert records == [
            AuditRecord(
                path="app/api-key",
                version=2,
                reason=f"key state is {expected_state.value}; rotation not allowed",
            )
        ]

    def test_never_created_rejected_by_default(self, kv, records):
        with pytest.raises(RotationStateError) as exc_info:
            rotate_secret(kv, "app/missing", lambda c: {"token": "new"},
                          audit=records.append)

        assert exc_info.value.state is KeyState.NEVER_CREATED
        assert exc_info.value.version is None
        assert kv.write_count == 0
        assert records[0].version is None

    def test_never_created_allowed_uses_cas_zero(self, kv, records):
        result = rotate_secret(
            kv, "app/missing",
            lambda current: {"token": "initial"},
            allow_states={KeyState.NEVER_CREATED},
            audit=records.append,
        )

        assert result["data"]["version"] == 1
        assert kv.read_secret_version("app/missing")["data"]["data"] == {
            "token": "initial"
        }

    def test_never_created_race_conflict(self, kv, records):
        """Both jobs see a missing key; only the first cas=0 create wins."""

        def competitor_creates_first(current):
            assert current is None
            kv.create_or_update_secret("app/missing", {"token": "other"}, cas=0)
            return {"token": "mine"}

        with pytest.raises(RotationConflictError) as exc_info:
            rotate_secret(
                kv, "app/missing", competitor_creates_first,
                allow_states={KeyState.NEVER_CREATED},
                audit=records.append,
            )

        assert exc_info.value.version is None
        assert kv.read_secret_version("app/missing")["data"]["data"] == {
            "token": "other"
        }

    def test_soft_deleted_allowed_when_opted_in(self, kv, records):
        kv.seed("app/api-key", {"token": "v2"}, version=2,
                deletion_time="2026-11-12T00:00:00Z")

        result = rotate_secret(
            kv, "app/api-key",
            lambda current: {"token": "revived"},
            allow_states={KeyState.SOFT_DELETED},
            audit=records.append,
        )

        assert result["data"]["version"] == 3
        assert records == []
