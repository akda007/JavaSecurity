package com.backendsec.backendsecurity.controllers;

import com.backendsec.backendsecurity.dto.AuthResult;
import com.backendsec.backendsecurity.dto.JwtUserData;
import com.backendsec.backendsecurity.dto.LoginData;
import com.backendsec.backendsecurity.models.User;
import com.backendsec.backendsecurity.repositories.UserRepository;
import com.backendsec.backendsecurity.services.JWTService;
import com.backendsec.backendsecurity.services.UserAuth;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserSecurityController {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JWTService<JwtUserData> jwt;

    @Autowired
    UserAuth userAuth;

    @PostMapping("login")
    public ResponseEntity<AuthResult> login(@RequestBody LoginData data) {
        var user = userAuth.loginByEmail(data.login());

        user = user != null ? user : userAuth.loginByUsername(data.login());

        if (user == null) {
            return ResponseEntity.status(401).body(new AuthResult("Unknown user!", null));
        }

        if (!passwordEncoder.matches(data.password(), user.getPassword())) {
            return ResponseEntity.status(401).body(new AuthResult("Wrong password!", null));
        }

        var token = jwt.get(new JwtUserData(user.getId()));

        return ResponseEntity.ok(new AuthResult("Success!", token));
    }


    @PostMapping("user")
    public ResponseEntity<String> create(@RequestBody User user) {
        if (user.getUsername() == null || user.getUsername().length() < 4) {
            return ResponseEntity.status(401).body("Invalid username!");
        }

        //TODO: email verification

       if (userAuth.loginByUsername(user.getUsername()) != null) {
           return ResponseEntity.status(401).body("User already exists!");
       }

       if (userAuth.loginByEmail(user.getEmail()) != null) {
           return ResponseEntity.status(401).body("Email already registered!");
       }

       var pw = user.getPassword();
       pw = passwordEncoder.encode(pw);
       user.setPassword(pw);


       userRepository.save(user);

       return ResponseEntity.ok("Success!");
    }
}
