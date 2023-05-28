import pytest
import re
from src.phase import Phase

APP_ID = "phApp:v1:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701"
APP_SECRET = "pss:v1:a7a0822aa4a4e4d37919009264200ba6ab978d92c8b4f7db5ae9ce0dfaf604fe:801605dfb89822ff52957abe39949bcfc44b9058ad81de58dd54fb0b110037b4b2bbde5a1143d31bbb3895f72e4ee52f5bd:625d395987f52c37022063eaf9b6260cad9ca03c99609213f899cae7f1bb04e7"


@pytest.fixture(scope="module")
def phase_instance():
    return Phase(APP_ID, APP_SECRET)


def test_phase_encrypt_returns_valid_ph(phase_instance):
    plaintext = "Signal"
    tag = "Phase Tag"
    PH_VERSION = "v1"

    ciphertext = phase_instance.encrypt(plaintext, tag)

    assert ciphertext is not None
    segments = ciphertext.split(":")
    assert len(segments) == 5
    assert segments[0] == "ph"
    assert segments[1] == PH_VERSION
    assert segments[4] == tag
    assert re.match("^[0-9a-f]+$", segments[2]) is not None
    assert re.match(
        "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=$)", segments[3]) is not None


def test_phase_encrypt_produces_same_length_ciphertexts(phase_instance):
    data = "hello world"
    num_of_trials = 10
    ciphertext_lengths = set()

    for _ in range(num_of_trials):
        ciphertext = phase_instance.encrypt(data)
        ciphertext_lengths.add(len(ciphertext))

    assert len(ciphertext_lengths) == 1
