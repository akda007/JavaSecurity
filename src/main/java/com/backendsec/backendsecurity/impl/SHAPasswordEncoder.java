package com.backendsec.backendsecurity.impl;

import org.aspectj.bridge.Message;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class SHAPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence rawPassword) {
        return encode(rawPassword.toString(), salt());
    }

    public String encode(String value, String salt) {
        value += salt;

        try {
            for (int i = 0; i < 1024; i++) {
                value = hash(value);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return value + "$" + salt;
    }


    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        var parts = encodedPassword.split("\\$");
        var expected = encode(rawPassword.toString(), parts[1]);

        return encodedPassword.equals(expected);
    }

    private String hash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] b = value.getBytes(StandardCharsets.UTF_8);
        byte[] encoded = md.digest(b);

        return toHex(encoded);
    }

    private String salt() {
        byte[] salt = new byte[32];
        new Random().nextBytes(salt);

        return toHex(salt);

    }

    private String toHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }

        return hexString.toString();

    }
}
