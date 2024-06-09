package com.example.digital_signature_demo.controller;

import com.example.digital_signature_demo.service.DocumentService;
import com.example.digital_signature_demo.model.User;
import com.example.digital_signature_demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/documents")
public class DocumentController {

    @Autowired
    private DocumentService documentService;

    @Autowired
    private UserService userService;

    @PostMapping("/sign")
    public ResponseEntity<byte[]> signDocument(@RequestParam("file") MultipartFile file, @RequestParam Long userId) {
        try {
            byte[] documentContent = file.getBytes();
            User user = userService.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
            byte[] signedDocument = documentService.signDocument(documentContent, user);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed_document.pdf");
            headers.add(HttpHeaders.CONTENT_TYPE, "application/pdf");

            return new ResponseEntity<>(signedDocument, headers, HttpStatus.OK);
        } catch (IOException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyDocument(@RequestParam("file") MultipartFile file) {
        try {
            byte[] documentContent = file.getBytes();
            Map<String, Object> verificationResult = documentService.verifyDocument(documentContent);

            return new ResponseEntity<>(verificationResult, HttpStatus.OK);
        } catch (IOException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
