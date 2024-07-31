package NovelRSA;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.time.Duration;
import java.time.Instant;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
public class NovelRSAMetricsCRT {

    private static final SecureRandom random = new SecureRandom();

    // Prime generation task class
    public static class PrimeGeneratorTask extends RecursiveTask<BigInteger> {
        private final int bitLength;

        public PrimeGeneratorTask(int bitLength) {
            this.bitLength = bitLength;
        }

        @Override
        protected BigInteger compute() {
            return BigInteger.probablePrime(bitLength, random);
        }
    }

    // Generate large prime using parallel processing
    public static BigInteger generateLargePrime(int bitLength) {
        ForkJoinPool pool = ForkJoinPool.commonPool();
        PrimeGeneratorTask task = new PrimeGeneratorTask(bitLength);
        return pool.invoke(task);
    }

    // Modular exponentiation task class
    public static class ModExpTask extends RecursiveTask<BigInteger> {
        private final BigInteger base, exp, mod;

        public ModExpTask(BigInteger base, BigInteger exp, BigInteger mod) {
            this.base = base;
            this.exp = exp;
            this.mod = mod;
        }

        @Override
        protected BigInteger compute() {
            return base.modPow(exp, mod);
        }
    }

    // CRT decryption function with parallel processing
    public static BigInteger crtDecrypt(BigInteger c, BigInteger p, BigInteger q, BigInteger r, BigInteger d,
                                        BigInteger dp, BigInteger dq, BigInteger dr, BigInteger pqinv, BigInteger prinv) throws ExecutionException, InterruptedException {
        ForkJoinPool forkJoinPool = ForkJoinPool.commonPool();

        ModExpTask taskM1 = new ModExpTask(c, dp, p);
        ModExpTask taskM2 = new ModExpTask(c, dq, q);
        ModExpTask taskM3 = new ModExpTask(c, dr, r);

        forkJoinPool.execute(taskM1);
        forkJoinPool.execute(taskM2);
        forkJoinPool.execute(taskM3);

        BigInteger m1 = taskM1.get();
        BigInteger m2 = taskM2.get();
        BigInteger m3 = taskM3.get();

        BigInteger h1 = pqinv.multiply(m1.subtract(m2)).mod(p);
        BigInteger h2 = prinv.multiply(m1.subtract(m3)).mod(p);
        return m2.add(h1.multiply(q)).add(h2.multiply(r));
    }

    public static void main(String[] args) throws ExecutionException, InterruptedException, IOException {
        int bitLength = 1024;

        // Start measuring key generation time
        Instant startKeyGen = Instant.now();

        // Parallel prime generation
        ForkJoinPool forkJoinPool = ForkJoinPool.commonPool();
        PrimeGeneratorTask task1 = new PrimeGeneratorTask(bitLength);
        PrimeGeneratorTask task2 = new PrimeGeneratorTask(bitLength);
        PrimeGeneratorTask task3 = new PrimeGeneratorTask(bitLength);

        // Submit tasks to the pool
        BigInteger p = forkJoinPool.submit(task1).get();
        BigInteger q = forkJoinPool.submit(task2).get();
        BigInteger r = forkJoinPool.submit(task3).get();

        // Ensure p != q != r
        while (p.equals(q)) {
            q = forkJoinPool.submit(new PrimeGeneratorTask(bitLength)).get();
        }
        while (p.equals(r) || q.equals(r)) {
            r = forkJoinPool.submit(new PrimeGeneratorTask(bitLength)).get();
        }

        BigInteger n = p.multiply(q).multiply(r);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)).multiply(r.subtract(BigInteger.ONE));

        BigInteger e = BigInteger.valueOf(65537); // Commonly used prime exponent
        BigInteger d = e.modInverse(phi);

        // Precompute values for CRT
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger dr = d.mod(r.subtract(BigInteger.ONE));
        BigInteger pqinv = q.modInverse(p);
        BigInteger prinv = r.modInverse(p);

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

        // Example plaintext and encryption
        BigInteger plaintext = new BigInteger("37141950242");

        // Start measuring encryption time
        Instant startEncryption = Instant.now();
        BigInteger ciphertext = modExp(plaintext, e, n);
        Instant endEncryption = Instant.now();
        Duration encryptionDuration = Duration.between(startEncryption, endEncryption);

        // Start measuring decryption time
        Instant startDecryption = Instant.now();
        BigInteger decryptedPlaintext = crtDecrypt(ciphertext, p, q, r, d, dp, dq, dr, pqinv, prinv);
        Instant endDecryption = Instant.now();
        Duration decryptionDuration = Duration.between(startDecryption, endDecryption);

        // Write results to file
        try (PrintWriter writer = new PrintWriter(new FileWriter(bitLength + "_novelrsa_metrics_crt.txt", true))) {
            writer.println("Plaintext to encrypt M: " + plaintext);
            writer.println("Prime p: " + p);
            writer.println("Prime q: " + q);
            writer.println("Prime r: " + r);
            writer.println("Modulus n: " + n);
            writer.println("Public Exponent e: " + e);
            writer.println("Private Exponent d: " + d);
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

    // Modular exponentiation using Exponentiation by Squaring
    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);

        while (exp.compareTo(BigInteger.ZERO) > 0) {
            if (exp.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                result = result.multiply(base).mod(mod);
            }
            exp = exp.shiftRight(1);
            base = base.multiply(base).mod(mod);
        }
        return result;
    }
}






