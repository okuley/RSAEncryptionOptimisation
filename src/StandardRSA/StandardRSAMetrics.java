package StandardRSA;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import java.time.Instant;
import java.time.Duration;

public class StandardRSAMetrics {
    public static void main(String[] args) throws Exception {
        //FileWriter writer = new FileWriter("rsa_metrics.txt");
        PrintWriter writer = new PrintWriter(new FileWriter("rsa_metrics.txt", true));

        // Key Generation
        Instant startTime = Instant.now();
        KeyPair keyPair = generateKeyPair();
        Instant endTime = Instant.now();
        Duration keyGenTime = Duration.between(startTime, endTime);

        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privKey = keyPair.getPrivate();

        writer.println("Key Generation Time: " + keyGenTime.toMillis() + " ms" );
        writer.println("Public Key: " + Base64.getEncoder().encodeToString(pubKey.getEncoded()) );
        writer.println("Private Key: " + Base64.getEncoder().encodeToString(privKey.getEncoded()) );

        // Measure memory consumption
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heapUsage = memoryBean.getHeapMemoryUsage();
        long usedMemory = heapUsage.getUsed();

        // Measure CPU usage
        OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
        double processCpuLoad = osBean.getSystemLoadAverage();

        // Encryption
        String plainText = "365343232";
        //BigInteger plaintext = new BigInteger("42");

        Instant encryptionStartTime = Instant.now();
        String encryptedText = encrypt(plainText, pubKey);
        //BigInteger encryptedText = encrypt(plainText, pubKey);
        Instant encryptionEndTime = Instant.now();
        Duration encryptionTime = Duration.between(encryptionStartTime, encryptionEndTime);
        writer.println("PlainText to Encrypt: " + plainText );
        writer.println("Encryption Time: " + encryptionTime.toMillis() + " ms" );
        writer.println("Encrypted Text: " + encryptedText );



        // Decryption

        Instant decryptionStartTime = Instant.now();
        String decryptedText = decrypt(encryptedText, privKey);
        Instant decryptionEndTime = Instant.now();
        Duration decryptionTime = Duration.between(decryptionStartTime, decryptionEndTime);

        writer.println("Decryption Time: " + decryptionTime.toMillis() + " ms" );
        writer.println("Decrypted Text: " + decryptedText );
        writer.println("Memory Consumption: " + usedMemory / (1024 * 1024) + " MB");
        writer.println("CPU Load: " + processCpuLoad);

        writer.close();
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyGen.initialize(2048, random);
        return keyGen.generateKeyPair();
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }
}



