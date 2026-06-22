package com.example.camt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class FileCrypto {

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATIONS = 65536;

    // =========================
    // ENCRYPT FILE
    // =========================
    public static void encryptFile(File input, File output, String password) throws Exception {

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (FileInputStream fis = new FileInputStream(input);
                FileOutputStream fos = new FileOutputStream(output)) {
            // Write salt + iv first (needed for decryption)
            fos.write(salt);
            fos.write(iv);

            CipherOutputStream cos = new CipherOutputStream(fos, cipher);

            byte[] buffer = new byte[4096];
            int read;

            while ((read = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, read);
            }

            cos.flush();
            cos.close();
        }

        System.out.println("Encryption complete: " + output.getAbsolutePath());
    }

    // =========================
    // DECRYPT FILE
    // =========================
    public static void decryptFile(File input, File output, String password) throws Exception {

        try (FileInputStream fis = new FileInputStream(input);
                FileOutputStream fos = new FileOutputStream(output)) {

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];

            fis.read(salt);
            fis.read(iv);

            SecretKey key = deriveKey(password, salt);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            CipherInputStream cis = new CipherInputStream(fis, cipher);

            byte[] buffer = new byte[4096];
            int read;

            while ((read = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
            }

            cis.close();
        }

        System.out.println("Decryption complete: " + output.getAbsolutePath());
    }

    // =========================
    // KEY DERIVATION (PBKDF2)
    // =========================
    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);

        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }

    // =========================
    // CLI MAIN
    // =========================
    static void main(String[] args) throws Exception {

        if (args.length < 4) {
            System.out.println("Usage:");
            System.out.println("  encrypt <input> <output> <password>");
            System.out.println("  decrypt <input> <output> <password>");
            return;
        }

        String mode = args[0];
        File input = new File(args[1]);
        File output = new File(args[2]);
        String password = args[3];

        if (mode.equalsIgnoreCase("encrypt")) {
            encryptFile(input, output, password);
        } else if (mode.equalsIgnoreCase("decrypt")) {
            decryptFile(input, output, password);
        } else {
            System.out.println("Unknown mode: " + mode);
        }
    }
}
