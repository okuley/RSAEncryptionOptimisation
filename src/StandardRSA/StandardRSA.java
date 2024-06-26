package StandardRSA;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
public class StandardRSA {
    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = generateKeyPair();
        String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        System.out.println("Public Key: " + publicKeyString);
        System.out.println("Private Key: " + privateKeyString);

        // Encrypt a message
        String plaintext = "Hello, RSA!";
        String encryptedText = encrypt(plaintext, publicKeyString);
        System.out.println("Encrypted Text: " + encryptedText);

        // Decrypt the message
        String decryptedText = decrypt(encryptedText, privateKeyString);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyGen.initialize(2048, random);
        return keyGen.generateKeyPair();
    }

    public static String encrypt(String plaintext, String publicKeyString) throws Exception {
        byte[] pubKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, String privateKeyString) throws Exception {
        byte[] privKeyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}




