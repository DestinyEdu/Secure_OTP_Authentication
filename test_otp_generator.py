import pytest

from otp_generator import OTPGenerator


class FakeClock:
    """Controllable clock so tests run instantly instead of sleeping."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def otp_system(clock):
    return OTPGenerator(
        expiry_seconds=120,
        max_generations=3,
        generation_window_seconds=60,
        max_failed_attempts=3,
        lockout_seconds=300,
        time_func=clock,
    )


def wrong_code(real_otp):
    return "000000" if real_otp != "000000" else "111111"


# ---------- Replay ----------
def test_otp_is_single_use(otp_system):
    otp = otp_system.generate_otp()
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_VERIFIED
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_NO_ACTIVE


# ---------- Expiry ----------
def test_otp_valid_before_expiry(otp_system, clock):
    otp = otp_system.generate_otp()
    clock.advance(119)
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_VERIFIED


def test_otp_rejected_after_expiry(otp_system, clock):
    otp = otp_system.generate_otp()
    clock.advance(121)
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_EXPIRED
    # Expired OTP is wiped, so it cannot be retried
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_NO_ACTIVE


# ---------- Rate limit window reset ----------
def test_generation_rate_limit_blocks_fourth_request(otp_system):
    for _ in range(3):
        assert otp_system.generate_otp() is not None
    assert otp_system.generate_otp() is None


def test_generation_allowed_again_after_window_reset(otp_system, clock):
    for _ in range(3):
        assert otp_system.generate_otp() is not None
    assert otp_system.generate_otp() is None      # blocked inside window

    clock.advance(61)                              # window passes
    assert otp_system.generate_otp() is not None   # allowed again


def test_block_is_still_active_just_before_window_ends(otp_system, clock):
    for _ in range(3):
        otp_system.generate_otp()
    clock.advance(59)
    assert otp_system.generate_otp() is None


# ---------- Lockout after 3 incorrect tries ----------
def test_warning_after_second_incorrect_attempt(otp_system):
    otp = otp_system.generate_otp()
    bad = wrong_code(otp)
    assert "Attempt 1 of 3" in otp_system.verify_otp(bad)
    assert otp_system.verify_otp(bad) == (
        "2 Incorrect OTPs, Temp Block if 3rd Attempt is Incorrect"
    )


def test_lock_after_third_incorrect_attempt(otp_system):
    otp = otp_system.generate_otp()
    bad = wrong_code(otp)
    otp_system.verify_otp(bad)
    otp_system.verify_otp(bad)
    assert otp_system.verify_otp(bad) == OTPGenerator.MSG_LOCKED
    # Even the correct OTP is rejected while locked
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_LOCKED


def test_generation_blocked_while_locked(otp_system):
    otp = otp_system.generate_otp()
    bad = wrong_code(otp)
    for _ in range(3):
        otp_system.verify_otp(bad)
    assert otp_system.generate_otp() is None


def test_lockout_expires(otp_system, clock):
    otp = otp_system.generate_otp()
    bad = wrong_code(otp)
    for _ in range(3):
        otp_system.verify_otp(bad)

    clock.advance(301)
    new_otp = otp_system.generate_otp()
    assert new_otp is not None
    assert otp_system.verify_otp(new_otp) == OTPGenerator.MSG_VERIFIED


def test_correct_otp_resets_failed_counter(otp_system):
    otp = otp_system.generate_otp()
    bad = wrong_code(otp)
    otp_system.verify_otp(bad)
    otp_system.verify_otp(bad)
    assert otp_system.verify_otp(otp) == OTPGenerator.MSG_VERIFIED
