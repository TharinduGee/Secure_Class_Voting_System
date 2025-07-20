import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ClassElectionCenter {
    private final List<BallotSubmission> submissions = new ArrayList<>();
    private Map<String, Integer> finalTally;
    private Set<String> usedTokens;

    public void postBallot(BallotSubmission submission) {
        submissions.add(submission);
        System.out.println("Election Center: New ballot posted. Total submissions: " + submissions.size());
    }

    public List<BallotSubmission> getAllSubmissions() {
        return Collections.unmodifiableList(submissions);
    }

    public void publishFinalTally(Map<String, Integer> tally, Set<String> tokens) {
        this.finalTally = tally;
        this.usedTokens = tokens;
        System.out.println("Election Center: Final results have been published.");
    }
}
