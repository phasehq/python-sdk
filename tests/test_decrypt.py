import pytest
from src.phase.phase import Phase

APP_ID = "phApp:v1:e0e50cb9a1953c610126b4092093b1beca51d08d91fc3d9f8d90482a32853215"
APP_SECRET = "pss:v1:d261abecb6708c18bebdb8b2748ee574e2b0bdeaf19b081a5f10006cc83d48d0:d146c8c6d326a7842ff9b2da0da455b3f7f568a70808e2eb0cfc5143d4fe170f:59e413612e06d75d251e3416361d0743345a9c9eda1cbcf2b1ef16e3077c011c"
APP_SECRET_INVALID = "pss:v1:d251abecb6708c18bebdb8b2748ee574e2b0bdeaf19b081a5f10006cc83d48d0:d146c8c6d326a7842ff9b2da0da455b3f7f568a70808e2eb0cfc5143d4fe170d:59e413612e06d75d251e3416361d0743345a9c9eda1cbcf2b1ef16e3077c012d"


@pytest.fixture(scope="module")
def phase_instance():
    return Phase(APP_ID, APP_SECRET)


def mock_fetch_app_key(appToken, wrapKey, appId, dataSize):
    return "e35ae9560207c90fa3dd68a8715e13a1ef988bffa284db73f04328df17f37cfe"


def test_phase_decrypt_returns_correct_plaintext(phase_instance, monkeypatch):
    data = "Signal"

    monkeypatch.setattr("src.phase.phase.fetch_app_key", mock_fetch_app_key)

    ciphertext = phase_instance.encrypt(data)

    plaintext = phase_instance.decrypt(ciphertext)

    assert plaintext is not None
    assert plaintext == data


def test_phase_decrypt_fails_with_incorrect_app_secret(monkeypatch):
    phase = Phase(APP_ID, APP_SECRET_INVALID)

    monkeypatch.setattr("src.phase.phase.fetch_app_key", mock_fetch_app_key)

    data = "Signal"
    ciphertext = phase.encrypt(data)

    with pytest.raises(ValueError, match="Something went wrong"):
        phase.decrypt(ciphertext)
