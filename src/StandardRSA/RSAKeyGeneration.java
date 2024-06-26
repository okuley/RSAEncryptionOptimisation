package StandardRSA;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;


public class RSAKeyGeneration {
    public static void main(String[] args) throws Exception {
        // Initialize the KeyPairGenerator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyGen.initialize(2048, random);

        // Generate the key pair
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey pubKey = pair.getPublic();
        PrivateKey privKey = pair.getPrivate();

        // Print the keys in Base64 format
        System.out.println("Public Key: " + java.util.Base64.getEncoder().encodeToString(pubKey.getEncoded()));
        System.out.println("Private Key: " + java.util.Base64.getEncoder().encodeToString(privKey.getEncoded()));
    }
}
