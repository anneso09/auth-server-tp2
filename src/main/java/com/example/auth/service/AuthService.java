package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service principal gérant l'inscription et la connexion des utilisateurs.
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * @param email l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return l'utilisateur créé
     */
    public User register(String email, String password) {
        // Validation email
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("Email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            throw new InvalidInputException("Format email invalide");
        }

        // Validation politique mot de passe (TP2)
        String policyError = passwordPolicyValidator.getErrorMessage(password);
        if (policyError != null) {
            throw new InvalidInputException(policyError);
        }

        // Vérifier si email existe déjà
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée : email déjà existant {}", email);
            throw new ResourceConflictException("Email déjà utilisé");
        }

        User user = new User(email, password); // le hash BCrypt viendra à l'étape suivante
        userRepository.save(user);
        logger.info("Inscription réussie pour {}", email);
        return user;
    }

    /**
     * Connecte un utilisateur existant et génère un token simple.
     * @param email l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return le token généré
     */
    public String login(String email, String password) {
        return userRepository.findByEmail(email)
                .map(user -> {
                    if (user.getPasswordHash().equals(password)) { // sera remplacé par BCrypt à l'étape suivante
                        String token = java.util.UUID.randomUUID().toString();
                        user.setToken(token);
                        userRepository.save(user);
                        logger.info("Connexion réussie pour {}", email);
                        return token;
                    } else {
                        logger.warn("Connexion échouée pour {}", email);
                        throw new AuthenticationFailedException("Email ou mot de passe incorrect");
                    }
                })
                .orElseThrow(() -> {
                    logger.warn("Connexion échouée : email inconnu {}", email);
                    return new AuthenticationFailedException("Email ou mot de passe incorrect");
                });
    }

    /**
     * Récupère un utilisateur par son token.
     * @param token le token de l'utilisateur
     * @return l'utilisateur correspondant
     */
    public java.util.Optional<User> getUserByToken(String token) {
        return userRepository.findByToken(token);
    }
}