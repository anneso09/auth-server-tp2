package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal d'authentification.
 * TP2 : améliore le stockage avec BCrypt mais ne protège pas encore contre le rejeu.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Inscrit un nouvel utilisateur.
     */
    public void register(String email, String password) {
        // Validation politique mot de passe
        String policyError = passwordPolicyValidator.getErrorMessage(password);
        if (policyError != null) {
            throw new InvalidInputException(policyError);
        }

        // Email unique
        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResourceConflictException("Email déjà utilisé.");
        }

        // Hacher le mot de passe
        String hash = passwordEncoder.encode(password);

        User user = new User(email, hash);
        userRepository.save(user);
    }

    /**
     * Connecte un utilisateur existant.
     */
    public String login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("Email ou mot de passe incorrect."));

        // Vérifier le mot de passe avec BCrypt
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new AuthenticationFailedException("Email ou mot de passe incorrect.");
        }

        // Générer un token simple
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);

        return token;
    }

    /**
     * Vérifie si un token est valide.
     */
    public boolean isTokenValid(String token) {
        return userRepository.findByToken(token).isPresent();
    }
}