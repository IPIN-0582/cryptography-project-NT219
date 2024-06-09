package com.example.digital_signature_demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "index";  // Tên file HTML mà bạn muốn phục vụ (không cần phần mở rộng .html)
    }
}
