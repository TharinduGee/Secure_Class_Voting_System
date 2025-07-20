public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("--- Setting up the Class Election Simulation ---");

        ElectionAuthority ea = new ElectionAuthority();
        TallyingAuthority ta = new TallyingAuthority();
        ClassElectionCenter bb = new ClassElectionCenter();

        Voter tharindu = new Voter("Tharindu", "123");
        Voter pabasara = new Voter("Pabasara", "456");
        Voter sahan = new Voter("Sahan", "789");
        Voter nuran = new Voter("Nuran", "000");

        System.out.println("\n--- Voter Registration Phase ---");
        tharindu.registerAndGetToken(ea);
        pabasara.registerAndGetToken(ea);
        sahan.registerAndGetToken(ea);
        nuran.registerAndGetToken(ea);

        System.out.println("\n--- Testing Double Registration ---");
        try {
            nuran.registerAndGetToken(ea);
        } catch (IllegalStateException e) {
            System.err.println("Error: " + e.getMessage());
        }

        System.out.println("\n--- Voting Phase ---");
        tharindu.castVote("Option A", ta, bb);
        pabasara.castVote("Option B", ta, bb);
        sahan.castVote("Option A", ta, bb);
        nuran.castVote("Option A", ta, bb);

        // Count results for the first time
        ta.tallyVotes(bb);

        // Demonstrate a replay attack : Nuran tries to vote again
        System.out.println("\n--- Testing Replay Attack ---");
        // For simulation, Nuran's submission will pass again as replay
        BallotSubmission nuranLastSubmission = bb.getAllSubmissions().get(3);
        System.out.println("Attacker resubmitting nuran's ballot...");
        bb.postBallot(nuranLastSubmission);
        // Count the votes again (remains same)
        ta.tallyVotes(bb);

        // Publishing final results
        System.out.println("\n--- Publishing Final Results ---");
        ta.publishResults(bb);
    }
}