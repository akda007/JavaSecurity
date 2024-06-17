package com.backendsec.backendsecurity.impl;

import com.backendsec.backendsecurity.models.User;
import com.backendsec.backendsecurity.repositories.UserRepository;
import com.backendsec.backendsecurity.services.UserAuth;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DefaultUserAuthService implements UserAuth {
    @Autowired
    private UserRepository repo;

    @Override
    public User loginByUsername(String username) {
        var users = repo.findByUsername(username);
        if (users.isEmpty()) return null;

        return users.get(0);
    }

    @Override
    public User loginByEmail(String email) {
        var users = repo.findByEmail(email);
        if (users.isEmpty()) return null;

        return users.get(0);
    }
}
