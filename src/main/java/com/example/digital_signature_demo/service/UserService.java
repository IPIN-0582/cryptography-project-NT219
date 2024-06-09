package com.example.digital_signature_demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.stereotype.Service;
import com.example.digital_signature_demo.model.User;
import com.example.digital_signature_demo.repository.UserRepository;

import java.util.Optional;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.Security;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.provider.DilithiumProvider;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    static {
        Security.addProvider(new DilithiumProvider());
    }

    public User registerUser(String username, String password) throws Exception {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
        kpg.initialize(DilithiumParameterSpec.LEVEL5, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        user.setPrivateKey(keyPair.getPrivate().getEncoded());
        user.setPublicKey(keyPair.getPublic().getEncoded());

        return userRepository.save(user);
    }

    public User loginUser(String username, String password) {
        User user = userRepository.findByUsername(username);
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            return user;
        }
        return null;
    }

    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(userRepository.findByUsername(username));
    }

    public User saveUser(User user) {
        return userRepository.save(user);
    }

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
}
