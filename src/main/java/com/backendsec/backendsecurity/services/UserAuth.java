package com.backendsec.backendsecurity.services;

import com.backendsec.backendsecurity.models.User;

public interface UserAuth {
    User loginByUsername(String username);
    User loginByEmail(String email);
}
