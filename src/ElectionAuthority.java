import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

public class ElectionAuthority {
    private final KeyPair keyPair;
    private final Set<String> registeredVoterIds = new HashSet<>();

    public ElectionAuthority() throws Exception {
        this.keyPair = CryptoUtils.generatePublicKeyPair();
        System.out.println("Election Authority initialized.");
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public EncryptedPayload issueToken(String voterId, PublicKey voterPublicKey) throws Exception{

        if (registeredVoterIds.contains(voterId)) {
            throw new IllegalStateException("Election Authority: Voter " + voterId + " has already registered.");
        }

        String token = UUID.randomUUID().toString();
        System.out.println("Generated Random Token: " + token);
        byte[] signature = CryptoUtils.sign(this.keyPair.getPrivate(), token.getBytes(StandardCharsets.UTF_8));
        System.out.println("Digital Signature (Base64): " + Base64.getEncoder().encodeToString(signature));
        SignedToken signedToken = new SignedToken(token, signature);
        byte[] serializedSignedToken = CryptoUtils.serialize(signedToken);
        System.out.println("Serialized SignedToken (hex): " + CryptoUtils.toHexString(serializedSignedToken));
        SecretKey sessionKey = CryptoUtils.generateSymmetricKey();
        System.out.println("Generated AES session key (hex): " + CryptoUtils.toHexString(sessionKey.getEncoded()));
        byte[] encryptedData = CryptoUtils.encryptSymmetric(sessionKey, serializedSignedToken);
        System.out.println("AES-encrypted SignedToken (hex): " + CryptoUtils.toHexString(encryptedData));
        byte[] encryptedKey = CryptoUtils.encryptAsymmetric(voterPublicKey, sessionKey.getEncoded());
        System.out.println("RSA-encrypted AES key (hex): " + CryptoUtils.toHexString(encryptedKey));
        EncryptedPayload payload = new EncryptedPayload(encryptedKey, encryptedData);

        registeredVoterIds.add(voterId);

        System.out.println("Election Authority: Issued and securely sent token to voter " + voterId+ "\n");
        return payload;
    }
}