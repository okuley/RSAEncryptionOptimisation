package StandardRSA;

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

public class StandardRSAMetricsNew {
    private static final SecureRandom random = new SecureRandom();

    // Generate large prime number
    public static BigInteger generateLargePrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, random);
    }

    // RSA Key Pair Generation
    public static class KeyPair {
        public BigInteger p,q,n, e, d;

        public KeyPair(BigInteger p,BigInteger q, BigInteger n, BigInteger e, BigInteger d) {
            this.p=p;
            this.q=q;
            this.n = n;
            this.e = e;
            this.d = d;
        }
    }

    public static KeyPair generateKeyPair(int bitLength) {
        BigInteger p = generateLargePrime(bitLength );
        BigInteger q = generateLargePrime(bitLength );
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = BigInteger.valueOf(65537); // Commonly used prime exponent
        BigInteger d = e.modInverse(phi);
        return new KeyPair(p,q,n, e, d);
    }

    // RSA Encryption
    public static BigInteger encrypt(BigInteger plaintext, KeyPair keyPair) {
        return plaintext.modPow(keyPair.e, keyPair.n);
    }

    // RSA Decryption
    public static BigInteger decrypt(BigInteger ciphertext, KeyPair keyPair) {
        return ciphertext.modPow(keyPair.d, keyPair.n);
    }

    public static void main(String[] args) throws IOException {
        int bitLength = 1024;

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
        BigInteger plaintext = new BigInteger("453435262");

        // Start measuring encryption time
        Instant startEncryption = Instant.now();
        BigInteger ciphertext = encrypt(plaintext, keyPair);
        Instant endEncryption = Instant.now();
        Duration encryptionDuration = Duration.between(startEncryption, endEncryption);

        // Start measuring decryption time
        Instant startDecryption = Instant.now();
        BigInteger decryptedPlaintext = decrypt(ciphertext, keyPair);
        Instant endDecryption = Instant.now();
        Duration decryptionDuration = Duration.between(startDecryption, endDecryption);

        // Write results to file
        try (PrintWriter writer = new PrintWriter(new FileWriter(bitLength+"_rsa_metrics.txt", true))) {
            writer.println("p: " + keyPair.p);
            writer.println("q: " + keyPair.q);
            writer.println("Modulus n: " + keyPair.n);
            writer.println("Public Exponent e: " + keyPair.e);
            writer.println("Private Exponent d: " + keyPair.d);
            writer.println("Ciphertext: " + ciphertext);
            writer.println("Decrypted Plaintext: " + decryptedPlaintext);
            writer.println("Key Generation Time: " + keyGenDuration.toMillis() + " ms");
            writer.println("Encryption Time: " + encryptionDuration.toMillis() + " ms");
            writer.println("Decryption Time: " + decryptionDuration.toMillis() + " ms");
            writer.println("Memory Consumption: " + usedMemory / (1024 * 1024) + " MB");
            writer.println("CPU Load: " + processCpuLoad);
            writer.println("");
        }

        // Print a message to indicate that results have been written to the file
        System.out.println("Performance metrics written to rsa_metrics.txt");
    }

}






