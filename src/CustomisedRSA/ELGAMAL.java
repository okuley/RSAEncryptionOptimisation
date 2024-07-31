package CustomisedRSA;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class ELGAMAL {

    private static final SecureRandom random = new SecureRandom();

    // Generate large prime number
    public static BigInteger generateLargePrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, random);
    }

    // ElGamal Key Pair Generation
    public static class KeyPair {
        public BigInteger p, g, y, x;

        public KeyPair(BigInteger p, BigInteger g, BigInteger y, BigInteger x) {
            this.p = p;
            this.g = g;
            this.y = y;
            this.x = x;
        }
    }

    public static KeyPair generateKeyPair(int bitLength) {
        BigInteger p = generateLargePrime(bitLength);
        BigInteger g = new BigInteger(bitLength, random).mod(p);
        BigInteger x = new BigInteger(bitLength - 1, random).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE); // Private key
        BigInteger y = g.modPow(x, p); // Public key y = g^x mod p
        return new KeyPair(p, g, y, x);
    }

    // ElGamal Encryption
    public static class Ciphertext {
        public BigInteger c1, c2;

        public Ciphertext(BigInteger c1, BigInteger c2) {
            this.c1 = c1;
            this.c2 = c2;
        }
    }

    public static Ciphertext encrypt(BigInteger plaintext, KeyPair keyPair) {
        BigInteger k = new BigInteger(keyPair.p.bitLength() - 1, random).mod(keyPair.p.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger c1 = keyPair.g.modPow(k, keyPair.p);
        BigInteger c2 = plaintext.multiply(keyPair.y.modPow(k, keyPair.p)).mod(keyPair.p);
        return new Ciphertext(c1, c2);
    }

    // ElGamal Decryption
    public static BigInteger decrypt(Ciphertext ciphertext, KeyPair keyPair) {
        BigInteger s = ciphertext.c1.modPow(keyPair.x, keyPair.p);
        BigInteger sInv = s.modInverse(keyPair.p);
        return ciphertext.c2.multiply(sInv).mod(keyPair.p);
    }

    public static void main(String[] args) throws IOException {
        int bitLength = 4096;

        // Start measuring key generation time
        Instant startKeyGen = Instant.now();

        // Key generation
        KeyPair keyPair = generateKeyPair(bitLength);

        // End measuring key generation time
        Instant endKeyGen = Instant.now();
        Duration keyGenDuration = Duration.between(startKeyGen, endKeyGen);

        // Measure memory consumption
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heapUsage = memoryBean.getHeapMemoryUsage();
        long usedMemory = heapUsage.getUsed();

        // Measure CPU usage
        OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
        double processCpuLoad = osBean.getSystemLoadAverage();

        // Example plaintext
        BigInteger plaintext = new BigInteger("46548100760");

        // Start measuring encryption time
        Instant startEncryption = Instant.now();
        Ciphertext ciphertext = encrypt(plaintext, keyPair);
        Instant endEncryption = Instant.now();
        Duration encryptionDuration = Duration.between(startEncryption, endEncryption);

        // Start measuring decryption time
        Instant startDecryption = Instant.now();
        BigInteger decryptedPlaintext = decrypt(ciphertext, keyPair);
        Instant endDecryption = Instant.now();
        Duration decryptionDuration = Duration.between(startDecryption, endDecryption);

        // Write results to file
        try (PrintWriter writer = new PrintWriter(new FileWriter(bitLength+"_elgamal_metrics.txt", true))) {
            writer.println("Prime p: " + keyPair.p);
            writer.println("Generator g: " + keyPair.g);
            writer.println("Public Key y: " + keyPair.y);
            writer.println("Private Key x: " + keyPair.x);
            writer.println("Ciphertext c1: " + ciphertext.c1);
            writer.println("Ciphertext c2: " + ciphertext.c2);
            writer.println("Decrypted Plaintext: " + decryptedPlaintext);
            writer.println("Key Generation Time: " + keyGenDuration.toMillis() + " ms");
            writer.println("Encryption Time: " + encryptionDuration.toMillis() + " ms");
            writer.println("Decryption Time: " + decryptionDuration.toMillis() + " ms");
            writer.println("Memory Consumption: " + usedMemory / (1024 * 1024) + " MB");
            writer.println("CPU Load: " + processCpuLoad);
            writer.println("");
        }

        // Print a message to indicate that results have been written to the file
        System.out.println("Performance metrics written to elgamal_metrics.txt");
    }

}



