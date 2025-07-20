import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class TallyingAuthority {
    private final KeyPair keyPair;
    private final Map<String, Integer> tallyResults = new HashMap<>();
    private final Set<String> usedTokens = new HashSet<>();

    public TallyingAuthority() throws Exception {
        this.keyPair = CryptoUtils.generatePublicKeyPair();
        System.out.println("Tallying Authority initialized.");
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public void tallyVotes(ClassElectionCenter cec) throws Exception {
        System.out.println("\n--- Tallying Authority starting the count ---");
        for (BallotSubmission submission : cec.getAllSubmissions()) {
            System.out.println("Tallying Authority: Processing ballot with token: " + submission.token().substring(0, 8));

            // Prevent replay attacks
            if (usedTokens.contains(submission.token())) {
                System.out.println("Tallying Authority: ERROR! Token has already been used. Discarding ballot.");
                continue;
            }

            // Verify the integrity and authenticity of the ballot
            byte[] ballotHash = CryptoUtils.hash(submission.ballot().toString().getBytes());
            byte[] dataShouldSigned = (submission.token() + CryptoUtils.toHexString(ballotHash)).getBytes();

            boolean signatureIsValid = CryptoUtils.verify(
                    submission.voterPublicKey(),
                    dataShouldSigned,
                    submission.signature()
            );

            if (!signatureIsValid) {
                System.out.println("Tallying Authority: Invalid signature. Discarding ballot.");
                continue;
            }

            System.out.println("TA: Signature is valid.");

            byte[] symmetricKeyBytes = CryptoUtils.decryptAsymmetric(keyPair.getPrivate(), submission.ballot().encryptedSymmetricKey());
            SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, 0, symmetricKeyBytes.length, "AES");
            byte[] decryptedVoteBytes = CryptoUtils.decryptSymmetric(symmetricKey, submission.ballot().encryptedVote());
            String voteChoice = new String(decryptedVoteBytes);

            System.out.println("Tallying Authority: Decrypted vote: " + voteChoice);

            tallyResults.put(voteChoice, tallyResults.getOrDefault(voteChoice, 0) + 1);
            usedTokens.add(submission.token());
        }
    }

    public void publishResults(ClassElectionCenter cec) {
        System.out.println("\n--- Final Election Results ---");
        for (Map.Entry<String, Integer> entry : tallyResults.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue() + " votes");
        }

        // For showcase and auditing purposes
        cec.publishFinalTally(tallyResults, usedTokens);
    }
}
