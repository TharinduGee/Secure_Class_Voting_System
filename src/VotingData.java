import java.io.Serializable;
import java.security.PublicKey;

record SignedToken(String token, byte[] signature) implements Serializable {}

record Ballot(byte[] encryptedVote, byte[] encryptedSymmetricKey) {}

record BallotSubmission(Ballot ballot, String token, PublicKey voterPublicKey, byte[] signature) {}

record EncryptedPayload(byte[] encryptedKey, byte[] encryptedData) implements Serializable {}