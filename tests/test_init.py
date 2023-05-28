from src.phase import Phase
import pytest

APP_ID_INVALID = "phApp:v1:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701"
APP_SECRET_INVALID = "pss:v1:a7a0822aa4a4e4d37919009264200ba6ab978d92c8b4f7db5ae9ce0dfaf604fe:801605dfb89822ff52957abe39949bcfc44b9058ad81de58dd54fb0b110037b4b2bbde5a1143d31bbb3895f72e4ee52f5bd:625d395987f52c37022063eaf9b6260cad9ca03c99609213f899cae7f1bb04e7"


@pytest.fixture(scope="module")
def phase_instance():
    return Phase(APP_ID_INVALID, APP_SECRET_INVALID)


def test_init_fails_with_invalid_app_id(phase_instance):
    invalid_app_id = "phApp:version:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701"
    with pytest.raises(ValueError, match="Invalid Phase APP_ID"):
        Phase(invalid_app_id, APP_SECRET_INVALID)


def test_test_init_fails_with_invalid_app_secret(phase_instance):
    invalid_app_secret = "pss:v1:00000000000000000000000000000000:00000000000000000000000000000000:00000000000000000000000000000000"
    with pytest.raises(ValueError, match="Invalid Phase APP_SECRET"):
        Phase(APP_ID_INVALID, invalid_app_secret)
