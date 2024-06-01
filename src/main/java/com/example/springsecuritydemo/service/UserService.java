package com.example.springsecuritydemo.service;

import com.example.springsecuritydemo.dao.entity.User;
import com.example.springsecuritydemo.dto.UserDto;
import com.example.springsecuritydemo.jwt.ChangePasswordRequest;

import java.security.Principal;
import java.util.Optional;

public interface UserService {

    Optional<User> getUserByUsername(String username);

    void updateUser(Long id, UserDto userDto);

    void deleteUser(Long id);
    //TODO: Cascading deletion
    //TODO: Password Reconfirmation

    void changePassword(ChangePasswordRequest request, Principal connectedUser);
}
