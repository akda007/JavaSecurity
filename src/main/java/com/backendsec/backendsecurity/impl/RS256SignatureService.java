package com.backendsec.backendsecurity.impl;

import com.backendsec.backendsecurity.services.HashService;
import com.backendsec.backendsecurity.services.KeyService;
import com.backendsec.backendsecurity.services.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Base64;
import java.util.concurrent.ExecutionException;

@Service
public class RS256SignatureService implements SignatureService {
    @Autowired
    KeyService keyService;

    @Autowired
    HashService hashService;

    @Override
    public String sign(String message) {
        KeyPair pair = keyService.getKeys();

        if (pair == null) {
            return null;
        }

        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(pair.getPrivate());
            rsa.update(hashService.hash(message));
            byte[] signature = rsa.sign();

            return Base64.getEncoder().encodeToString(signature);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean verify(String message, String signature) {
        KeyPair pair = keyService.getKeys();

        if (pair == null) return false;

        try {
            Signature sig = Signature.getInstance("SHA256withRSA");

            sig.initVerify(pair.getPublic());
            sig.update(hashService.hash(message));
            byte[] signatureBytes = Base64.getDecoder().decode(signature);

            return sig.verify(signatureBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
