"""Secure OTP generator with expiry, single-use codes, generation rate
limiting and temporary lockout after repeated incorrect attempts."""

import hashlib
import hmac
import logging
import secrets
import time

logger = logging.getLogger(__name__)


class OTPGenerator:
    # Messages returned by verify_otp()
    MSG_VERIFIED = "OTP verified successfully."
    MSG_NO_ACTIVE = "No active OTP."
    MSG_EXPIRED = "OTP expired."
    MSG_WARNING = "2 Incorrect OTPs, Temp Block if 3rd Attempt is Incorrect"
    MSG_LOCKED = "OTP locked after 3 incorrect attempts. Temporarily blocked."

    def __init__(
        self,
        otp_length=6,
        expiry_seconds=120,
        max_generations=3,
        generation_window_seconds=60,
        max_failed_attempts=3,
        lockout_seconds=300,
        time_func=time.monotonic,  # injectable so tests don't need sleep()
    ):
        self.otp_length = otp_length
        self.expiry_seconds = expiry_seconds
        self.max_generations = max_generations
        self.generation_window_seconds = generation_window_seconds
        self.max_failed_attempts = max_failed_attempts
        self.lockout_seconds = lockout_seconds
        self._now = time_func

        self._otp_hash = None          # only a hash of the OTP is stored
        self._expires_at = None
        self._generation_times = []
        self._failed_attempts = 0
        self._locked_until = None

    # ---------- helpers ----------
    @staticmethod
    def _hash(otp):
        return hashlib.sha256(otp.encode()).hexdigest()

    def _clear_otp(self):
        self._otp_hash = None
        self._expires_at = None

    def is_locked(self):
        if self._locked_until is None:
            return False
        if self._now() >= self._locked_until:
            # Lockout period over: reset the counters
            self._locked_until = None
            self._failed_attempts = 0
            logger.info("Lockout expired, OTP verification re-enabled")
            return False
        return True

    # ---------- public API ----------
    def generate_otp(self):
        """Return a new OTP string, or None if blocked."""
        now = self._now()

        if self.is_locked():
            logger.warning("OTP generation blocked: account temporarily locked")
            return None

        # Keep only requests inside the sliding window
        self._generation_times = [
            t for t in self._generation_times
            if now - t < self.generation_window_seconds
        ]
        if len(self._generation_times) >= self.max_generations:
            logger.warning("OTP generation rate limit exceeded")
            return None

        otp = f"{secrets.randbelow(10 ** self.otp_length):0{self.otp_length}d}"
        self._otp_hash = self._hash(otp)
        self._expires_at = now + self.expiry_seconds
        self._failed_attempts = 0
        self._generation_times.append(now)
        logger.info("OTP generated successfully")
        return otp

    def verify_otp(self, otp):
        """Return a status message describing the result."""
        if self.is_locked():
            logger.warning("Verification attempted while locked")
            return self.MSG_LOCKED

        if self._otp_hash is None:
            return self.MSG_NO_ACTIVE

        if self._now() >= self._expires_at:
            self._clear_otp()
            logger.warning("OTP expired")
            return self.MSG_EXPIRED

        # Constant-time comparison of hashes
        if hmac.compare_digest(self._hash(str(otp)), self._otp_hash):
            self._clear_otp()          # single use
            self._failed_attempts = 0
            logger.info("OTP verified successfully")
            return self.MSG_VERIFIED

        self._failed_attempts += 1
        logger.warning("Failed OTP attempt: %d", self._failed_attempts)

        if self._failed_attempts >= self.max_failed_attempts:
            self._locked_until = self._now() + self.lockout_seconds
            self._clear_otp()
            logger.error("OTP locked after maximum failed attempts")
            return self.MSG_LOCKED

        if self._failed_attempts == self.max_failed_attempts - 1:
            return self.MSG_WARNING

        return f"Incorrect OTP. Attempt {self._failed_attempts} of {self.max_failed_attempts}."
