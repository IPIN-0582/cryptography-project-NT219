package com.example.digital_signature_demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.digital_signature_demo.model.User;
import com.example.digital_signature_demo.service.UserService;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestParam String username, @RequestParam String password) {
        try {
            userService.registerUser(username, password);
            return ResponseEntity.status(201).body("Registration successful!");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("An error occurred during registration: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<User> loginUser(@RequestParam String username, @RequestParam String password) {
        User user = userService.loginUser(username, password);
        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.status(401).build();
        }
    }

    @GetMapping("/check-usb")
    public ResponseEntity<List<String>> checkUsb() {
        List<String> usbDrives = getUsbDrives();
        return ResponseEntity.ok(usbDrives);
    }

    private List<String> getUsbDrives() {
        List<String> usbDrives = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            try {
                Process process = Runtime.getRuntime().exec("wmic logicaldisk where drivetype=2 get deviceid");
                process.waitFor();
                java.io.InputStream is = process.getInputStream();
                java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
                String result = s.hasNext() ? s.next() : "";

                String[] lines = result.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.equalsIgnoreCase("DeviceID")) {
                        usbDrives.add(line + "\\");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (os.contains("nux") || os.contains("nix")) {
            File mediaDir = new File("/media");
            if (mediaDir.exists() && mediaDir.isDirectory()) {
                File[] devices = mediaDir.listFiles();
                if (devices != null) {
                    for (File device : devices) {
                        if (device.isDirectory() && isUsbDrive(device)) {
                            usbDrives.add(device.getAbsolutePath());
                        }
                    }
                }
            }
        }

        return usbDrives;
    }

    private boolean isUsbDrive(File device) {
        File devById = new File("/dev/disk/by-id");
        if (devById.exists() && devById.isDirectory()) {
            File[] ids = devById.listFiles();
            if (ids != null) {
                for (File id : ids) {
                    if (id.getName().contains("usb") && id.getAbsolutePath().contains(device.getName())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
