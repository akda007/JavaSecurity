package com.backendsec.backendsecurity.impl;

import com.backendsec.backendsecurity.services.JWTService;
import com.backendsec.backendsecurity.services.SignatureService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Service
public class DefalultJwtService<T> implements JWTService<T> {
    @Autowired
    SignatureService signatureService;

    @Override
    public String get(T obj) {
        try {
            ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();

            String json = ow.writeValueAsString(obj);
            String base64Json = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

            String header = "{\"alg\":\"Bcrypt\",\"typ\":\"JWT\"}";
            String b64Header = Base64.getEncoder().encodeToString(header.getBytes(StandardCharsets.UTF_8));

            String signature = signatureService.sign(b64Header + "." + base64Json);

            return b64Header + "." + base64Json + "." + signature;

        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }

    }

    @Override
    public Map<String, Object> validate(String jwt) {
        var parts = jwt.split("\\.");
        var header = parts[0];
        var payload = parts[1];
        var signature = parts[2];

        if (!signatureService.verify(header + "." + payload, signature)) {
            return null;
        }

        try {
            var json = Utf8.decode(Base64.getDecoder().decode(payload));

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> map = objectMapper.readValue(json, Map.class);
            return map;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
