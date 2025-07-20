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
        byte[] sessionKeyBytes = CryptoUtils.decryptAsymmetric(keyPair.getPrivate(), payload.encryptedKey());
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
        byte[] serializedSignedToken = CryptoUtils.decryptSymmetric(sessionKey, payload.encryptedData());
        SignedToken signedToken = (SignedToken) CryptoUtils.deserialize(serializedSignedToken);
        System.out.println("Voter " + regNo + ": Successfully decrypted the token payload.");

        boolean isAuthentic = CryptoUtils.verify(
                ea.getPublicKey(),
                signedToken.token().getBytes(StandardCharsets.UTF_8),
                signedToken.signature()
        );

        if (!isAuthentic) {
            throw new SecurityException("Voter " + regNo + ": verification failed! The token is not sent by EA.");
        }

        this.token = signedToken.token();
        System.out.println("Voter " + regNo + ": Token is authentic. Registration complete.");
    }
    
    public void castVote(String voteChoice, TallyingAuthority ta, ClassElectionCenter cec) throws Exception {
        if (token == null) {
            System.out.println("Voter " + name + " cannot vote without a token. Contact EA");
            return;
        }

        System.out.println("\nVoter " + regNo + " is casting a vote for: " + voteChoice);

        SecretKey symmetricKey = CryptoUtils.generateSymmetricKey();
        byte[] encryptedVote = CryptoUtils.encryptSymmetric(symmetricKey, voteChoice.getBytes());
        byte[] encryptedSymmetricKey = CryptoUtils.encryptAsymmetric(ta.getPublicKey(), symmetricKey.getEncoded());

        Ballot ballot = new Ballot(encryptedVote, encryptedSymmetricKey);
        byte[] ballotHash = CryptoUtils.hash(ballot.toString().getBytes());

        byte[] dataToSign = (token + CryptoUtils.toHexString(ballotHash)).getBytes();
        byte[] signature = CryptoUtils.sign(keyPair.getPrivate(), dataToSign);
        BallotSubmission submission = new BallotSubmission(ballot, token, keyPair.getPublic(), signature);

        cec.postBallot(submission);
        System.out.println("Voter " + regNo + " successfully submitted their ballot to the Election Center.");
    }
}