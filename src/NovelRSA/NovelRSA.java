package NovelRSA;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;

public class NovelRSA {
    private static final SecureRandom random = new SecureRandom();

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

    public static BigInteger generateLargePrime(int bitLength) {
        ForkJoinPool pool = ForkJoinPool.commonPool();
        PrimeGeneratorTask task = new PrimeGeneratorTask(bitLength);
        return pool.invoke(task);
    }

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

    public static BigInteger crtDecrypt(BigInteger c, BigInteger p, BigInteger q, BigInteger d, BigInteger dp, BigInteger dq, BigInteger qinv) {
        BigInteger m1 = modExp(c, dp, p);
        BigInteger m2 = modExp(c, dq, q);
        BigInteger h = qinv.multiply(m1.subtract(m2)).mod(p);
        return m2.add(h.multiply(q));
    }

    public static void main(String[] args) throws ExecutionException, InterruptedException {
        int bitLength = 1024;

        // Parallel prime generation
        ForkJoinPool forkJoinPool = ForkJoinPool.commonPool();
        PrimeGeneratorTask task1 = new PrimeGeneratorTask(bitLength);
        PrimeGeneratorTask task2 = new PrimeGeneratorTask(bitLength);

        // Submit tasks to the pool
        BigInteger p = forkJoinPool.submit(task1).get();
        BigInteger q = forkJoinPool.submit(task2).get();

        // Ensure p != q
        while (p.equals(q)) {
            q = forkJoinPool.submit(new PrimeGeneratorTask(bitLength)).get();
        }

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = BigInteger.valueOf(65537); // Commonly used prime exponent
        BigInteger d = e.modInverse(phi);

        // Precompute values for CRT
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger qinv = q.modInverse(p);

        // Example plaintext and encryption
        BigInteger plaintext = new BigInteger("42");
        BigInteger ciphertext = modExp(plaintext, e, n);

        System.out.println("Prime p: " + p);
        System.out.println("Prime q: " + q);
        System.out.println("Modulus n: " + n);
        System.out.println("Public Exponent e: " + e);
        System.out.println("Private Exponent d: " + d);
        System.out.println("Ciphertext: " + ciphertext);

        // Decryption using CRT
        BigInteger decryptedPlaintext = crtDecrypt(ciphertext, p, q, d, dp, dq, qinv);
        System.out.println("Decrypted Plaintext: " + decryptedPlaintext);
    }
}





