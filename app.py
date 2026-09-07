"""Core login service for the CanteenGo prototype."""

from dataclasses import dataclass
import hashlib
import hmac
import secrets


@dataclass
class User:
    """Stored user data; the plain-text password is never retained."""

    email: str
    password_hash: str
    failed_attempts: int = 0
    locked: bool = False


class LoginService:
    """Authenticate users without requiring an external database."""

    _ALGORITHM = "pbkdf2_sha256"
    _ITERATIONS = 600_000
    _SALT_BYTES = 16
    _KEY_BYTES = 32
    _MAX_FAILED_ATTEMPTS = 5

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def register(self, email: str, password: str) -> None:
        """Register one user and reject invalid or duplicate accounts."""
        normalized_email = self._normalize_email(email)
        self._validate_password(password)

        if normalized_email in self._users:
            raise ValueError("An account with this email already exists")

        self._users[normalized_email] = User(
            email=normalized_email,
            password_hash=self._hash_password(password),
        )

    def login(self, email: str, password: str) -> str:
        """Return a session token for valid credentials."""
        normalized_email = self._normalize_email(email)
        user = self._users.get(normalized_email)

        if user is None or user.locked:
            raise PermissionError("Invalid email or password")

        if not self._verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= self._MAX_FAILED_ATTEMPTS:
                user.locked = True
            raise PermissionError("Invalid email or password")

        user.failed_attempts = 0
        return secrets.token_urlsafe(32)

    @staticmethod
    def _normalize_email(email: str) -> str:
        normalized_email = email.strip().lower()
        if "@" not in normalized_email or normalized_email.startswith("@"): 
            raise ValueError("A valid email is required")
        return normalized_email

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

    @classmethod
    def _hash_password(cls, password: str) -> str:
        salt = secrets.token_bytes(cls._SALT_BYTES)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, cls._ITERATIONS, cls._KEY_BYTES
        )
        return f"{cls._ALGORITHM}${cls._ITERATIONS}${salt.hex()}${digest.hex()}"

    @classmethod
    def _verify_password(cls, password: str, stored_hash: str) -> bool:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != cls._ALGORITHM:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt_hex),
            int(iterations),
            cls._KEY_BYTES,
        )
        return hmac.compare_digest(candidate.hex(), digest_hex)


def main() -> None:
    service = LoginService()
    service.register("student@canteengo.com", "CanteenGo123")
    token = service.login("STUDENT@CANTEENGO.COM", "CanteenGo123")
    print(f"Login successful. Session token created: {token[:8]}...")


if __name__ == "__main__":
    main()
