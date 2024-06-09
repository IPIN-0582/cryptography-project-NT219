package com.example.digital_signature_demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.digital_signature_demo.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
