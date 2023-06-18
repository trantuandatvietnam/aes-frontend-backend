package com.sopromadze.blogapi.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class AESUtils {
    private static final String ALGORITHM = "AES";
    private static final String KEY = "BuJo|%nEaV>9g\\%63I~_M.tv?Y\"?(tBX";

    public static String decrypt(String encryptedPayload) {
        try {
            String iv = encryptedPayload.substring(0, 24);
            String encryptedData = encryptedPayload.substring(24);

            byte[] keyBytes = KEY.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = encryptedData.getBytes();
            byte[] ivBytes = Base64.getDecoder().decode(iv);

            Security.addProvider(new BouncyCastleProvider());

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            IvParameterSpec ivParams = new IvParameterSpec(ivBytes);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParams);

            byte[] decodedData = Base64.getDecoder().decode(ciphertextBytes);
            byte[] decryptedBytes = cipher.doFinal(decodedData);
            return new String(decryptedBytes, StandardCharsets.UTF_8).trim();
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static String encrypt(String message) {
        try {
            byte[] keyBytes = KEY.getBytes(StandardCharsets.UTF_8);
            byte[] plaintextBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] ivBytes = new byte[16];

            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(ivBytes);

            Security.addProvider(new BouncyCastleProvider());

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            IvParameterSpec ivParams = new IvParameterSpec(ivBytes);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);

            byte[] encryptedBytes = cipher.doFinal(plaintextBytes);
            byte[] encodedData = Base64.getEncoder().encode(encryptedBytes);
            byte[] encodedIV = Base64.getEncoder().encode(ivBytes);

            String encryptedData = new String(encodedData, StandardCharsets.UTF_8);
            String encodedIVString = new String(encodedIV, StandardCharsets.UTF_8);

            return encodedIVString + encryptedData;
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

}