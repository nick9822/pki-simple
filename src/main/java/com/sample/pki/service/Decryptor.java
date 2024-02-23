package com.sample.pki.service;

import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class Decryptor {

    private PublicKey pubk;

    // this will be private
    public void loadAllKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] pubkb = Base64.getDecoder().decode(new FileSystemResource("mykey.pem").getContentAsString(StandardCharsets.UTF_8));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec pubkSpec = new X509EncodedKeySpec(pubkb);

        this.pubk = keyFactory.generatePublic(pubkSpec);
    }

    public String decrypt(String enmsg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher dcipher = Cipher.getInstance("RSA");
        dcipher.init(Cipher.DECRYPT_MODE, this.pubk);

        byte[] msgBytes = dcipher.doFinal(Base64.getDecoder().decode(enmsg));
        return new String(msgBytes, StandardCharsets.UTF_8);
    }
}
