import logging
import os

from flask import Flask, jsonify, request

from otp_generator import OTPGenerator

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/otp_security.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("otp_api")

app = Flask(__name__)
otp_system = OTPGenerator()


@app.post("/generate")
def generate():
    otp = otp_system.generate_otp()
    if otp is None:
        log.warning("Generate request blocked from %s", request.remote_addr)
        return jsonify(status="blocked", message="Rate limited or locked"), 429
    # Lab only: OTP is printed on the server, simulating SMS/email delivery.
    print(f"[SIMULATED DELIVERY] OTP: {otp}")
    log.info("Generate request allowed from %s", request.remote_addr)
    return jsonify(status="generated"), 200


@app.post("/verify")
def verify():
    data = request.get_json(silent=True) or {}
    result = otp_system.verify_otp(str(data.get("otp", "")))
    log.info("Verify request from %s -> %s", request.remote_addr, result)
    if result == OTPGenerator.MSG_VERIFIED:
        code = 200
    elif result == OTPGenerator.MSG_LOCKED:
        code = 423
    else:
        code = 401
    return jsonify(message=result), code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
