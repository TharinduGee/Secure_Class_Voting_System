import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;

public class CryptoUtils {

    private static final String ASYMMETRIC_ALGO = "RSA";
    private static final String SYMMETRIC_ALGO = "AES";
    private static final String HASH_ALGO = "SHA-256";
    private static final String SIGNATURE_ALGO = "SHA256withRSA";

    public static KeyPair generatePublicKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGO);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGO);
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public static byte[] encryptAsymmetric(PublicKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptAsymmetric(PrivateKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] encryptSymmetric(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptSymmetric(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGO);
        return digest.digest(data);
    }

    public static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature privateSignature = Signature.getInstance(SIGNATURE_ALGO);
        privateSignature.initSign(privateKey);
        privateSignature.update(data);
        return privateSignature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature publicSignature = Signature.getInstance(SIGNATURE_ALGO);
        publicSignature.initVerify(publicKey);
        publicSignature.update(data);
        return publicSignature.verify(signature);
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] serialize(Object obj) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(obj);
            return bos.toByteArray();
        }
    }

    public static Object deserialize(byte[] data) throws Exception {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream in = new ObjectInputStream(bis)) {
            return in.readObject();
        }
    }
}