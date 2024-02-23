package com.sample.pki.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Service
public class RSAKeysGenerator {

    @Autowired
    private Encryptor encryptor;

    @Autowired
    private Decryptor decryptor;

    @PostConstruct
    private void init() throws NoSuchAlgorithmException, IOException {
        this.generate("mykey", 512); // intentionally loose

        try {
            encryptor.loadAllKeys();
            decryptor.loadAllKeys();
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        String msg = "hi there";

        String en = "";
        try {
            en = encryptor.encrypt(msg);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String op = "";
        try {
            op = decryptor.decrypt(en);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        System.out.println(msg.equals(op));
    }

    public void generate(String keyName, int keySize) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(keySize);
        KeyPair pair = gen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        try (FileOutputStream fos = new FileOutputStream(keyName+".key")) {
            fos.write(privateKey.getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream(keyName+".pem")) {
            Base64.Encoder encoder = Base64.getEncoder();
            String publicKeyStr = encoder.encodeToString(publicKey.getEncoded());
            fos.write(publicKeyStr.getBytes(StandardCharsets.UTF_8));
        }
    }
}