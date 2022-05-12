package shared.hashing.encoder;

import org.junit.jupiter.api.Test;
import shared.hashing.codec.HashingEncoder;
import shared.hashing.validator.HashingValidator;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class HashingEncoderTest {
    @Test
    void testHashingEncoderMD4() throws NoSuchAlgorithmException {
        if (!HashingValidator.isHashingAlgorithmSupported("MD4")) {
            return; // Some JVM implementations don't support MD4
        }
        // Test vectors: https://en.wikipedia.org/wiki/MD4#MD4_test_vectors
        final String raw = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        byte[] encoded = HashingEncoder.createDigest("MD4", raw);
        assertEquals(HashingEncoder.bytesToHex(encoded), "e33b4ddc9c38f2199c3e7b164fcc0536");
    }

    @Test
    void testHashingEncoderMD5() throws NoSuchAlgorithmException {
        // Test vectors: https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data
        final String raw = "abc";
        byte[] encoded = HashingEncoder.createDigest("MD5", raw);
        assertEquals(HashingEncoder.bytesToHex(encoded), "900150983cd24fb0d6963f7d28e17f72");
    }

    @Test
    void testHashingEncoderSHA256() throws NoSuchAlgorithmException {
        // Test vector: https://www.di-mgt.com.au/sha_testvectors.html
        final String raw = "abc";
        byte[] encoded = HashingEncoder.createDigest("SHA-256", raw);
        assertEquals(HashingEncoder.bytesToHex(encoded), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void testHashingEncoderSHA512() throws NoSuchAlgorithmException {
        // Test vector: https://www.di-mgt.com.au/sha_testvectors.html
        final String raw = "abc";
        byte[] encoded = HashingEncoder.createDigest("SHA-512", raw);
        assertEquals(HashingEncoder.bytesToHex(encoded),
                     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }
}