package com.backendsec.backendsecurity.impl;

import com.backendsec.backendsecurity.services.KeyService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyService implements KeyService {
    KeyPair keyPair = null;

    @Override
    public KeyPair getKeys() {
        try{
            generateKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    void generateKeyPair() throws NoSuchAlgorithmException {
        if (keyPair != null) {
            return;
        }

        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }
}
