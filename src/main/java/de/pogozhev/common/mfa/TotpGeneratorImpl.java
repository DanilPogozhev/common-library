package de.pogozhev.common.mfa;

import de.pogozhev.common.mfa.exceptions.MFAGeneratorException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

class TotpGeneratorImpl implements MFAGenerator {
    private static final String HMAC_ALGORITHM = "HmacSHA3-512";
    private static final int DIGITS = 6;
    private static final int TIME_INTERVAL = 30;

    @Override
    public String generate(String privateKey) {
        long currentTime = Instant.now().getEpochSecond();
        try {
            // Convert the secret key to bytes
            byte[] keyBytes = privateKey.getBytes();
            // Create a secret key spec for the HMAC algorithm
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
            // Initialize the HMAC algorithm with the secret key spec
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secretKeySpec);

            // Convert the current time to bytes
            byte[] timeBytes = ByteBuffer.allocate(8).putLong(currentTime / TIME_INTERVAL).array();
            // Compute the HMAC value
            byte[] hmacValue = mac.doFinal(timeBytes);

            // Calculate the offset and truncate the HMAC value
            int offset = hmacValue[hmacValue.length - 1] & 0xF;
            int binary = ((hmacValue[offset] & 0x7F) << 24) |
                    ((hmacValue[offset + 1] & 0xFF) << 16) |
                    ((hmacValue[offset + 2] & 0xFF) << 8) |
                    (hmacValue[offset + 3] & 0xFF);

            // Calculate the OTP by taking the modulo of the binary value
            int otpValue = binary % (int) Math.pow(10, DIGITS);

            // Convert the OTP to a string with leading zeros if necessary
            return String.format("%0" + DIGITS + "d", otpValue);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new MFAGeneratorException("Exception during generation TOTP code", e);
        }
    }
}
