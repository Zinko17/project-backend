package com.example.clicker.service;

import com.example.clicker.dto.LoginRequest;
import com.example.clicker.dto.RegisterRequest;
import com.example.clicker.entity.User;
import com.example.clicker.repository.UserRepository;
import com.example.clicker.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public String register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername()))
            throw new RuntimeException("Username is already in use");

        if (!request.getPassword().equals(request.getConfirmPassword()))
            throw new RuntimeException("Passwords do not match");

        validatePasswordStrength(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(User.Role.USER)
                .build();

        userRepository.save(user);
        return jwtService.generateToken(user.getUsername());
    }

    public String login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Username not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword()))
            throw new RuntimeException("Passwords don't match");

        return jwtService.generateToken(user.getUsername());
    }

    public void validatePasswordStrength(String password) {
        if (!password.matches(".*[A-Z].*"))
            throw new RuntimeException("Password must contain at least one uppercase letter");

        if (!password.matches(".*\\d.*"))
            throw new RuntimeException("Password must contain at least one digit");

        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*"))
            throw new RuntimeException("Password must contain at least one special character");
    }

}
