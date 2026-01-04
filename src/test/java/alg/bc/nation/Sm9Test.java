package alg.bc.nation;

import alg.bc.nation.sm9.Sm9;
import alg.bc.nation.sm9.Sm9JniLoader;
import alg.bc.nation.sm9.Sm9Native;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class Sm9Test {

    @BeforeClass
    public static void setUp() {
        boolean avail = Sm9.available();
        System.out.println("SM9 Available: " + avail);
        if (!avail) {
            System.err.println("Warning: SM9 JNI library load failed: " + Sm9JniLoader.getLastError());
        }
    }

    @Test
    public void testEncFlow() {
        if (!Sm9.available())
            return;

        try {
            // 1. Generate Master Key Pair (ENC)
            // msk = master private, mpk = master public
            byte[][] masterKeyPair = Sm9Native.kgcGenerateMasterKeyPair(1); // 1=ENC
            Assert.assertNotNull(masterKeyPair);
            Assert.assertEquals(2, masterKeyPair.length);
            byte[] mskEnc = masterKeyPair[0];
            byte[] mpkEnc = masterKeyPair[1];
            Assert.assertNotNull(mskEnc);
            Assert.assertNotNull(mpkEnc);

            // 2. Derive User Private Key
            String userId = "user-enc@example.com";
            byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8);
            byte[] skEnc = Sm9Native.kgcDeriveUserPrivateKey(1, mskEnc, userIdBytes);
            Assert.assertNotNull(skEnc);

            // 3. Encrypt
            String plaintext = "Hello SM9 Encryption";
            byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] cipher = Sm9Native.encrypt(mpkEnc, userIdBytes, plainBytes);
            Assert.assertNotNull(cipher);

            // 4. Decrypt
            byte[] decrypted = Sm9Native.decrypt(skEnc, userIdBytes, cipher);
            Assert.assertNotNull(decrypted);
            Assert.assertArrayEquals(plainBytes, decrypted);

            System.out.println("SM9 Encryption/Decryption Test Passed");

        } catch (UnsatisfiedLinkError e) {
            System.err.println(
                    "Native method mismatch (expected if package changed but DLL not rebuilt): " + e.getMessage());
            // We fail the test to signal strict requirement
            throw e;
        }
    }

    @Test
    public void testSignFlow() {
        if (!Sm9.available()) return;

        try {
            // 1. Generate Master Key Pair (SIGN)
            byte[][] masterKeyPair = Sm9Native.kgcGenerateMasterKeyPair(2); // 2=SIGN
            Assert.assertNotNull(masterKeyPair);
            Assert.assertEquals(2, masterKeyPair.length);
            byte[] mskSign = masterKeyPair[0];
            byte[] mpkSign = masterKeyPair[1]; // mpkSign is public key used for verify

            // 2. Derive User Private Key
            String userId = "user-sign@example.com";
            byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8);
            byte[] skSign = Sm9Native.kgcDeriveUserPrivateKey(2, mskSign, userIdBytes);
            Assert.assertNotNull(skSign);

            // 3. Sign
            String msg = "Content to be signed";
            byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
            byte[] signature = Sm9Native.sign(skSign, userIdBytes, msgBytes);
            Assert.assertNotNull(signature);

            // 4. Verify
            boolean valid = Sm9Native.verify(mpkSign, userIdBytes, msgBytes, signature);
            Assert.assertTrue("Signature verification failed", valid);
            
            System.out.println("SM9 Sign/Verify Test Passed");

        } catch (UnsatisfiedLinkError e) {
             System.err.println("Native method mismatch: " + e.getMessage());
             throw e;
        }
    }
}
