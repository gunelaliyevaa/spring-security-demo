package com.example.springsecuritydemo.service.impl;

import com.example.springsecuritydemo.dao.entity.User;
import com.example.springsecuritydemo.dao.repo.UserRepository;
import com.example.springsecuritydemo.dto.UserDto;
import com.example.springsecuritydemo.jwt.ChangePasswordRequest;
import com.example.springsecuritydemo.service.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository repository;

    private final PasswordEncoder encoder;


    @Override
    public Optional<User> getUserByUsername(String username) {
        var user = repository.findByUsername(username).orElseThrow();
        return Optional.of(user);
    }

    @Override
    @Transactional
    public void updateUser(Long id, UserDto userDto) {
        this.repository.findById(id)
                .ifPresent(user -> {
                    user.setUsername(userDto.getUsername());
                    user.setEmail(userDto.getEmail());
                    repository.save(user);
                });
        //TODO: Implement Token Refresh
    }

    @Override
    public void deleteUser(Long id) {
        this.repository.deleteById(id);
        //TODO: Ask for password reconfirmation
    }

    @Override
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // Check if the current password is correct
        if (!encoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Wrong password!");
        }

        // Check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Passwords are not matching!");
        }
        user.setPassword(encoder.encode(request.getNewPassword())); // Update the password
        repository.save(user);
    }


    //TODO: DO I NEED TO CHANGE TOKEN AGAIN??
}