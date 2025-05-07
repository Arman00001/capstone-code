package com.capstone.hors;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * HORS Signature scheme implementation
 */
public class HORS {

    /**
     * {@code N}: Bit size of each secret key element
     */
    private final int N;

    /**
     * {@code T}: The number of secret key values
     */
    private final int T;

    /**
     * {@code K}: The number of secret key elements used in each signature
     */
    private final int K;

    /**
     * {@code secretKey}: The secret key used for signing the message
     */
    private byte[][] secretKey;

    /**
     * {@code publicKey}: The public key used for verifying the signature
     */
    private byte[][] publicKey;

    /**
     * {@code digest}: One-way or hash function used for digesting or hashing values
     */
    private final MessageDigest digest = MessageDigest.getInstance("SHA-256");


    /**
     * Constructor to initialize HORS scheme on custom variables
     * @param N Bit size of each secret key element
     * @param T The number of secret key values
     * @param K The number of secret key elements used in each signature
     * @throws NoSuchAlgorithmException: If the given hashing function does not exist
     */
    public HORS(int N, int T, int K) throws NoSuchAlgorithmException {
        this.N = N;
        this.T = T;
        this.K = K;
    }

    /**
     * Function to generate secret and public keys
     */
    public void generateKeys() {
        SecureRandom random = new SecureRandom();
        byte[][] secretKey = new byte[T][N];
        byte[][] publicKey = new byte[T][N];

        for (int i = 0; i < T; i++) {
            random.nextBytes(secretKey[i]);
            publicKey[i] = digest.digest(secretKey[i]);
        }

        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    /**
     * Function used to sign the given message
     * @param message The given message to be signed
     * @param secretKey Used to sign the message
     * @return The signature of the given {@code message}
     */
    public byte[][] signMessage(byte[] message, byte[][] secretKey) {
        byte[] hashedMessage = digest.digest(message);
        byte[][] signature = new byte[K][];
        int[] indices = getIndices(hashedMessage);

        for (int i = 0; i < signature.length; i++) {
            signature[i] = Arrays.copyOf(secretKey[indices[i]], N);
        }

        return signature;
    }

    /**
     * Function to verify the {@code signature} of the given {@code message}
     * @param message The given message
     * @param signature Signature of the given {@code message}
     * @param publicKey Public key for verifying the {@code signature} of {@code message}
     * @return {@code true} if the given {@code signature} belongs to the {@code message},
     *         {@code false} otherwise
     */
    public boolean verifySignature(byte[] message, byte[][] signature, byte[][] publicKey) {
        byte[] hashedMessage = digest.digest(message);
        int[] indices = getIndices(hashedMessage);

        for (int i = 0; i < K; i++) {
            byte[] hashedSignature = digest.digest(signature[i]);

            if (!Arrays.equals(hashedSignature, publicKey[indices[i]])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Splits the hashed message, interprets each element as an integer
     * @param hashedMessage The hashed message
     * @return Splitted hashed message as an array of integers
     *
     */
    private int[] getIndices(byte[] hashedMessage) {
        int substringLength = (int) (Math.log(T) / Math.log(2));
        int[] indices = new int[K];
        int bitIndex = 0;

        for (int i = 0; i < K; i++) {
            int index = 0;
            for (int j = 0; j < substringLength; j++) {
                int byteIndex = (bitIndex + j) / 8 % hashedMessage.length;
                int bitPosition = 7 - ((bitIndex + j) % 8);
                int bit = (hashedMessage[byteIndex] >> bitPosition) & 1;

                index = (index << 1) | bit;
            }
            indices[i] = index % T;
            bitIndex += substringLength;
        }
        return indices;
    }

    /**
     * Returns the secret key
     * @return Initialized scheme's secret key
     */
    public byte[][] getSecretKey() {
        return secretKey;
    }

    /**
     * Returns the public key
     * @return Initialized scheme's public key
     */
    public byte[][] getPublicKey() {
        return publicKey;
    }
}