package NovelRSA;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;
public class NovelRSANEW {

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

    // CRT decryption function
    public static BigInteger crtDecrypt(BigInteger c, BigInteger p, BigInteger q, BigInteger r, BigInteger d,
                                        BigInteger dp, BigInteger dq, BigInteger dr, BigInteger pqinv, BigInteger prinv) {
        BigInteger m1 = modExp(c, dp, p);
        BigInteger m2 = modExp(c, dq, q);
        BigInteger m3 = modExp(c, dr, r);
        BigInteger h1 = pqinv.multiply(m1.subtract(m2)).mod(p);
        BigInteger h2 = prinv.multiply(m1.subtract(m3)).mod(p);
        return m2.add(h1.multiply(q)).add(h2.multiply(r));
    }

    // Main method for RSA key generation, encryption, and decryption
    public static void main(String[] args) throws ExecutionException, InterruptedException {
        int bitLength = 1024;

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

        // Example plaintext and encryption
        BigInteger plaintext = new BigInteger("426");
        BigInteger ciphertext = modExp(plaintext, e, n);

        System.out.println("Prime p: " + p);
        System.out.println("Prime q: " + q);
        System.out.println("Prime r: " + r);
        System.out.println("Modulus n: " + n);
        System.out.println("Public Exponent e: " + e);
        System.out.println("Private Exponent d: " + d);
        System.out.println("Ciphertext: " + ciphertext);

        // Decryption using CRT
        BigInteger decryptedPlaintext = crtDecrypt(ciphertext, p, q, r, d, dp, dq, dr, pqinv, prinv);
        System.out.println("Decrypted Plaintext: " + decryptedPlaintext);
    }
}




