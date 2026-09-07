import pytest

from app import LoginService


def test_login_accepts_valid_credentials_and_normalizes_email():
    service = LoginService()
    service.register("student@canteengo.com", "CanteenGo123")

    token = service.login(" STUDENT@CANTEENGO.COM ", "CanteenGo123")

    assert token
    assert len(token) >= 32


def test_password_is_hashed_and_not_stored_in_plain_text():
    service = LoginService()
    service.register("student@canteengo.com", "CanteenGo123")

    stored_user = service._users["student@canteengo.com"]

    assert stored_user.password_hash != "CanteenGo123"
    assert stored_user.password_hash.startswith("pbkdf2_sha256$")


def test_login_rejects_wrong_password():
    service = LoginService()
    service.register("student@canteengo.com", "CanteenGo123")

    with pytest.raises(PermissionError, match="Invalid email or password"):
        service.login("student@canteengo.com", "wrong-password")


def test_account_locks_after_five_failed_attempts():
    service = LoginService()
    service.register("student@canteengo.com", "CanteenGo123")

    for _ in range(5):
        with pytest.raises(PermissionError):
            service.login("student@canteengo.com", "wrong-password")

    with pytest.raises(PermissionError):
        service.login("student@canteengo.com", "CanteenGo123")

    assert service._users["student@canteengo.com"].locked is True


@pytest.mark.parametrize(
    "email,password",
    [("invalid-email", "CanteenGo123"), ("student@example.com", "short")],
)
def test_registration_validates_input(email, password):
    service = LoginService()

    with pytest.raises(ValueError):
        service.register(email, password)
