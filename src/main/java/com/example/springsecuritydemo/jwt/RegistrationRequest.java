package com.example.springsecuritydemo.jwt;

import com.example.springsecuritydemo.enums.Role;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RegistrationRequest {

    String username;

    String email;

    String password;

    Role role;
}
