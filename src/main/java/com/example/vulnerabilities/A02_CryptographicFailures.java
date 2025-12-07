package com.example.vulnerabilities;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Random;

/**
 * OWASP A02:2021 - Cryptographic Failures
 *
 * Demonstrates failures related to cryptography which often leads to sensitive data exposure.
 */
public class A02_CryptographicFailures {

    /**
     * VULNERABILITY: Hardcoded Encryption Key
     * Encryption key is hardcoded in source code
     */
    private static final String ENCRYPTION_KEY = "MySecretKey12345";

    /**
     * VULNERABILITY: Weak Cryptographic Algorithm (DES)
     * DES is deprecated and easily broken
     */
    public byte[] encryptWithDES(String data) throws Exception {
        // INSECURE: DES is a weak algorithm
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * VULNERABILITY: Weak Hash Algorithm (MD5)
     * MD5 is cryptographically broken and should not be used
     */
    public String hashPasswordMD5(String password) throws Exception {
        // INSECURE: MD5 is broken, vulnerable to collisions
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    /**
     * VULNERABILITY: Weak Hash Algorithm (SHA-1)
     * SHA-1 is deprecated and vulnerable to collision attacks
     */
    public String hashPasswordSHA1(String password) throws Exception {
        // INSECURE: SHA-1 is deprecated
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    /**
     * VULNERABILITY: Insecure Random Number Generator
     * Using Random instead of SecureRandom for security-sensitive operations
     */
    public String generateSessionToken() {
        // INSECURE: Random is predictable, use SecureRandom instead
        Random random = new Random();
        long token = random.nextLong();
        return Long.toHexString(token);
    }

    /**
     * VULNERABILITY: ECB Mode Encryption
     * ECB mode reveals patterns in encrypted data
     */
    public byte[] encryptWithECB(String data) throws Exception {
        // INSECURE: ECB mode is not semantically secure
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * VULNERABILITY: Null Cipher (No Encryption)
     * Using NullCipher provides no encryption
     */
    public String storePassword(String password) {
        // INSECURE: Storing passwords in plaintext
        return password;
    }

    /**
     * VULNERABILITY: Static IV (Initialization Vector)
     * Reusing IV makes encryption deterministic
     */
    private static final byte[] STATIC_IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    public byte[] getStaticIV() {
        // INSECURE: Static IV should never be reused
        return STATIC_IV;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
