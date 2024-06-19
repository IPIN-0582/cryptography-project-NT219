package com.example.digital_signature_demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.digital_signature_demo.model.User;
import com.example.digital_signature_demo.repository.UserRepository;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;
import java.util.Optional;
import java.util.ArrayList;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
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
        if (userRepository.findByUsername(username) != null) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
        kpg.initialize(DilithiumParameterSpec.LEVEL3, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        saveKeysToExternalStorage(privateKey, publicKey, username);

        return userRepository.save(user);
    }

    private void saveKeysToExternalStorage(byte[] privateKey, byte[] publicKey, String username) throws Exception {
        List<String> externalDrives = getExternalDrives();

        if (externalDrives.isEmpty()) {
            throw new Exception("No external storage found.");
        }

        // Use the first available external drive
        File externalDrive = new File(externalDrives.get(0));

        Path userDir = Paths.get(externalDrive.getAbsolutePath(), username);
        Files.createDirectories(userDir);

        File privateKeyFile = new File(userDir.toFile(), "privateKey.key");
        File publicKeyFile = new File(userDir.toFile(), "publicKey.key");

        try (FileOutputStream privateKeyFos = new FileOutputStream(privateKeyFile);
             FileOutputStream publicKeyFos = new FileOutputStream(publicKeyFile)) {
            privateKeyFos.write(privateKey);
            publicKeyFos.write(publicKey);
        }
    }

    private List<String> getExternalDrives() {
        List<String> externalDrives = new ArrayList<>();
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
                        externalDrives.add(line + "\\");
                    }
                }
            } catch (Exception e) {e.printStackTrace();}
        } else if (os.contains("nux") || os.contains("nix")) {
            File mediaDir = new File("/media");
            if (mediaDir.exists() && mediaDir.isDirectory()) {
                File[] devices = mediaDir.listFiles();
                if (devices != null) {
                    for (File device : devices) {
                        if (device.isDirectory() && isUsbDrive(device)) {
                            externalDrives.add(device.getAbsolutePath());
                        }
                    }
                }
            }
        }
        return externalDrives;
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

    public byte[] getPrivateKeyFromUSB(String username) throws Exception {
        List<String> externalDrives = getExternalDrives();

        if (externalDrives.isEmpty()) {
            throw new Exception("No external storage found.");
        }

        File externalDrive = new File(externalDrives.get(0));
        Path privateKeyPath = Paths.get(externalDrive.getAbsolutePath(), username, "privateKey.key");

        if (!Files.exists(privateKeyPath)) {
            throw new Exception("Private key not found.");
        }

        return Files.readAllBytes(privateKeyPath);
    }

    public byte[] getPublicKeyFromUSB(String username) throws Exception {
        List<String> externalDrives = getExternalDrives();

        if (externalDrives.isEmpty()) {
            throw new Exception("No external storage found.");
        }

        File externalDrive = new File(externalDrives.get(0));
        Path privateKeyPath = Paths.get(externalDrive.getAbsolutePath(), username, "publicKey.key");

        if (!Files.exists(privateKeyPath)) {
            throw new Exception("Private key not found.");
        }

        return Files.readAllBytes(privateKeyPath);
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
