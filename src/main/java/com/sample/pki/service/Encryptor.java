package com.sample.pki.service;

import jakarta.annotation.PostConstruct;
import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class Encryptor {

    private PrivateKey pk;

    // this will be private
    public void loadAllKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] pkb = new FileSystemResource("mykey.key").getContentAsByteArray();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec pkSpec = new PKCS8EncodedKeySpec(pkb);

        this.pk = keyFactory.generatePrivate(pkSpec);
    }

    public String encrypt(String msg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, this.pk);

        byte[] encryptedMsg = encryptCipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedMsg);
    }
}
