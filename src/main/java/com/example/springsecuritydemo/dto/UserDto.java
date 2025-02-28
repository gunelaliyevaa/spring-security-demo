package com.example.springsecuritydemo.dto;

import com.example.springsecuritydemo.enums.Role;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserDto{

    String username;

    String email;

    Role roles;
}
