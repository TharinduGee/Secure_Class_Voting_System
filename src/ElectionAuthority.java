import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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

        byte[] signature = CryptoUtils.sign(this.keyPair.getPrivate(), token.getBytes(StandardCharsets.UTF_8));
        SignedToken signedToken = new SignedToken(token, signature);
        byte[] serializedSignedToken = CryptoUtils.serialize(signedToken);
        SecretKey sessionKey = CryptoUtils.generateSymmetricKey();
        byte[] encryptedData = CryptoUtils.encryptSymmetric(sessionKey, serializedSignedToken);
        byte[] encryptedKey = CryptoUtils.encryptAsymmetric(voterPublicKey, sessionKey.getEncoded());
        EncryptedPayload payload = new EncryptedPayload(encryptedKey, encryptedData);

        registeredVoterIds.add(voterId);

        System.out.println("Election Authority: Issued and securely sent token to voter " + voterId);
        return payload;
    }
}