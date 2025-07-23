import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class Voter {
    private final String name;
    private final String regNo;
    private final KeyPair keyPair;
    private String token;

    public Voter(String name, String regNo) throws Exception {
        this.name = name;
        this.regNo = regNo;
        this.keyPair = CryptoUtils.generatePublicKeyPair();
    }

    public void registerAndGetToken(ElectionAuthority ea) throws Exception {
        System.out.println("Voter " + name + " with regNo: " + regNo +  " is registering with the Election Authority.");

        EncryptedPayload payload = ea.issueToken(regNo, this.keyPair.getPublic());
        System.out.println("Received EncryptedPayload from EA");

        byte[] sessionKeyBytes = CryptoUtils.decryptAsymmetric(keyPair.getPrivate(), payload.encryptedKey());

        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
        System.out.println("Decrypted session key. Encoded value (hex): " + CryptoUtils.toHexString(sessionKey.getEncoded()));

        byte[] serializedSignedToken = CryptoUtils.decryptSymmetric(sessionKey, payload.encryptedData());
        System.out.println("Decrypted signed token (serialized, hex): " + CryptoUtils.toHexString(serializedSignedToken));

        SignedToken signedToken = (SignedToken) CryptoUtils.deserialize(serializedSignedToken);
        System.out.println("Deserialized SignedToken object: token=" + signedToken.token());

        boolean isAuthentic = CryptoUtils.verify(
                ea.getPublicKey(),
                signedToken.token().getBytes(StandardCharsets.UTF_8),
                signedToken.signature()
        );
        System.out.println("Verification of token signature: " + (isAuthentic ? "SUCCESS" : "FAILED"));

        if (!isAuthentic) {
            throw new SecurityException("Voter " + regNo + ": verification failed! The token is not sent by EA.");
        }

        this.token = signedToken.token();
        System.out.println("Voter " + regNo + ": Token is authentic. Registration complete.\n\n\n");
    }


    public void castVote(String voteChoice, TallyingAuthority ta, ClassElectionCenter cec) throws Exception {
        if (token == null) {
            System.out.println("Voter " + name + " cannot vote without a token. Contact EA");
            return;
        }

        System.out.println("\nVoter " + regNo + " is casting a vote for: " + voteChoice);

        SecretKey symmetricKey = CryptoUtils.generateSymmetricKey();
        System.out.println("Generated symmetric AES key (hex): " + CryptoUtils.toHexString(symmetricKey.getEncoded()));

        byte[] encryptedVote = CryptoUtils.encryptSymmetric(symmetricKey, voteChoice.getBytes());
        System.out.println("Encrypted vote (hex): " + CryptoUtils.toHexString(encryptedVote));

        byte[] encryptedSymmetricKey = CryptoUtils.encryptAsymmetric(ta.getPublicKey(), symmetricKey.getEncoded());
        System.out.println("Encrypted symmetric AES key using TA's public key (hex): " + CryptoUtils.toHexString(encryptedSymmetricKey));

        Ballot ballot = new Ballot(encryptedVote, encryptedSymmetricKey);
        System.out.println("Created Ballot object");

        byte[] ballotHash = CryptoUtils.hash(ballot.toString().getBytes());
        System.out.println("Computed ballot hash (hex): " + CryptoUtils.toHexString(ballotHash));

        byte[] dataToSign = (token + CryptoUtils.toHexString(ballotHash)).getBytes();
        System.out.println("Data to be signed (hex): " + CryptoUtils.toHexString(dataToSign));

        byte[] signature = CryptoUtils.sign(keyPair.getPrivate(), dataToSign);
        System.out.println("Generated digital signature (Base64): " + java.util.Base64.getEncoder().encodeToString(signature));

        BallotSubmission submission = new BallotSubmission(ballot, token, keyPair.getPublic(), signature);

        cec.postBallot(submission);
        System.out.println("Voter " + regNo + " successfully submitted their ballot to the Election Center.\n\n\n");
    }

}