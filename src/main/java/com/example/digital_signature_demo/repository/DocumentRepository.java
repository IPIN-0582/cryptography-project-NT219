package com.example.digital_signature_demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import  com.example.digital_signature_demo.model.Document;

public interface DocumentRepository extends JpaRepository<Document, Long> {
}
