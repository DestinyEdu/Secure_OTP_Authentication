from otp_generator import OTPGenerator

s = OTPGenerator()
otp = s.generate_otp()
print("Generated OTP:", otp)
print("Attempt 1 (wrong):  ", s.verify_otp("000000"))
print("Attempt 2 (wrong):  ", s.verify_otp("000000"))
print("Attempt 3 (wrong):  ", s.verify_otp("000000"))
print("Correct OTP after lock:", s.verify_otp(otp))
