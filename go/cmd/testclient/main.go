// testclient exercises the pinion-prover HTTP API using a local state file.
// Start the prover with INSECURE_DEV_AUTH_USER_HINT set to bypass JWT validation.
//
// This is a port of pinion-prover's own cmd/testclient onto the
// proverclient library in this repo, so it no longer needs to import
// pinion-prover's (private-repo) models package or duplicate the HTTP/async
// polling logic inline; this file is now just command wiring and local
// state-file bookkeeping; proverclient.Client does the rest.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	proverclient "github.com/pinionengineering/pinion-prover-client/go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	flagBaseURL  = "base-url"
	flagState    = "state"
	envProverURL = "PROVER_URL"
)

// clientState is the JSON state file schema.
type clientState struct {
	Server      string              `json:"server"`
	KeyID       string              `json:"key_id,omitempty"`
	Protocol    string              `json:"protocol,omitempty"`
	ClientSetup []byte              `json:"client_setup,omitempty"`
	Roots       map[string]rootInfo `json:"roots,omitempty"`
	Pending     *pendingState       `json:"pending,omitempty"`
}

type rootInfo struct {
	// Exactly one of BlockIDs/BlockCount is populated, matching whichever the
	// server returned: BlockIDs for CID-addressed protocols (Ateniese,
	// Erway, BJO), BlockCount for chunked protocols (sw-priv, sw-pub) that
	// virtualize the root into super-blocks addressed by rootCID||localIndex.
	BlockIDs   []string `json:"block_ids,omitempty"`
	BlockCount int      `json:"block_count,omitempty"`
}

type pendingState struct {
	Challenge []byte   `json:"challenge"`
	Roots     []string `json:"roots"`
	Proof     []byte   `json:"proof,omitempty"`
}

func main() {
	godotenv.Load()

	rootCmd := &cobra.Command{
		Use:   "testclient",
		Short: "Test client for the pinion-prover service",
		Long: `testclient exercises the pinion-prover HTTP API using a local state file.

Start the prover with INSECURE_DEV_AUTH_USER_HINT set to bypass JWT validation,
then run commands in sequence to exercise the full proof flow.`,
	}

	rootCmd.PersistentFlags().String(flagBaseURL, "http://localhost:8766/prover", "prover service base URL (including the /prover path prefix)")
	rootCmd.PersistentFlags().String(flagState, ".prover-state.json", "path to state file")
	viper.BindPFlag(flagBaseURL, rootCmd.PersistentFlags().Lookup(flagBaseURL))
	viper.BindPFlag(flagState, rootCmd.PersistentFlags().Lookup(flagState))
	viper.BindEnv(flagBaseURL, envProverURL)
	viper.AutomaticEnv()

	rootCmd.AddCommand(
		keyCreateCmd(),
		tagCmd(),
		setupCmd(),
		importCmd(),
		challengeCmd(),
		proveCmd(),
		verifyCmd(),
		auditCmd(),
		statusCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// --- Commands ---

func keyCreateCmd() *cobra.Command {
	var protocol, label string

	cmd := &cobra.Command{
		Use:   "key-create",
		Short: "Create a challenge key on the server and save it to state",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			st.Server = apiBase()

			resp, err := client().CreateKey(cmd.Context(), protocol, label)
			if err != nil {
				return fmt.Errorf("key-create: %w", err)
			}

			st.KeyID = resp.KeyID
			st.Protocol = protocol
			st.ClientSetup = resp.ClientSetup
			st.Roots = make(map[string]rootInfo)
			st.Pending = nil
			saveState(st)

			fmt.Printf("key created  key_id=%s  protocol=%s\n", resp.KeyID, protocol)
			return nil
		},
	}
	cmd.Flags().StringVar(&protocol, "protocol", "sw-pub", "protocol: sw-priv or sw-pub")
	cmd.Flags().StringVar(&label, "label", "", "optional human-readable name for the key")
	return cmd
}

func tagCmd() *cobra.Command {
	var roots []string

	cmd := &cobra.Command{
		Use:   "tag",
		Short: "Tag one or more roots under the current key",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			if st.KeyID == "" {
				return fmt.Errorf("no key in state: run key-create first")
			}
			if st.Roots == nil {
				st.Roots = make(map[string]rootInfo)
			}

			for _, root := range roots {
				result, err := client().Tag(cmd.Context(), root, st.KeyID, &proverclient.TagOptions{
					OnProgress: func(p proverclient.TagJobProgress, status string) {
						fmt.Printf("  %s  %s  %d/%d blocks\n", root, status, p.CompletedBlocks, p.TotalBlocks)
					},
				})
				if err != nil {
					return fmt.Errorf("tag %s: %w", root, err)
				}
				st.Roots[root] = rootInfo{BlockIDs: result.BlockIDs, BlockCount: result.BlockCount}
				fmt.Printf("tagged  root=%s  blocks=%d\n", root, len(result.BlockIDs)+result.BlockCount)
			}

			saveState(st)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&roots, "root", nil, "root CID to tag (repeatable)")
	cmd.MarkFlagRequired("root")
	return cmd
}

func setupCmd() *cobra.Command {
	var keyID string

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Bootstrap state from the server (for a fresh client or after state loss)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			if keyID == "" {
				keyID = st.KeyID
			}
			if keyID == "" {
				return fmt.Errorf("no key_id: provide --key-id or run key-create first")
			}

			resp, err := client().GetSetup(cmd.Context(), keyID)
			if err != nil {
				return fmt.Errorf("setup: %w", err)
			}

			st.Server = apiBase()
			st.KeyID = keyID
			st.ClientSetup = resp.ClientSetup
			st.Roots = make(map[string]rootInfo, len(resp.Roots))
			for _, tr := range resp.Roots {
				st.Roots[tr.Root] = rootInfo{BlockIDs: tr.BlockIDs, BlockCount: tr.BlockCount}
			}
			st.Pending = nil
			saveState(st)

			fmt.Printf("setup complete  key_id=%s  roots=%d\n", keyID, len(resp.Roots))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyID, "key-id", "", "key ID to bootstrap from (defaults to state's key_id)")
	return cmd
}

func importCmd() *cobra.Command {
	var keyFile, rootsFile string

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Load state from files exported by the dashboard (Export key file / Export roots)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyFile == "" && rootsFile == "" {
				return fmt.Errorf("specify --key-file and/or --roots-file")
			}
			st := loadState()

			if keyFile != "" {
				data, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("read key file: %w", err)
				}
				var kf struct {
					Server      string `json:"server"`
					KeyID       string `json:"key_id"`
					Protocol    string `json:"protocol"`
					ClientSetup []byte `json:"client_setup"`
				}
				if err := json.Unmarshal(data, &kf); err != nil {
					return fmt.Errorf("decode key file: %w", err)
				}
				st.Server = kf.Server
				st.KeyID = kf.KeyID
				st.Protocol = kf.Protocol
				st.ClientSetup = kf.ClientSetup
				fmt.Printf("imported key  key_id=%s  protocol=%s\n", kf.KeyID, kf.Protocol)
			}

			if rootsFile != "" {
				data, err := os.ReadFile(rootsFile)
				if err != nil {
					return fmt.Errorf("read roots file: %w", err)
				}
				var rf struct {
					KeyID string                    `json:"key_id"`
					Roots []proverclient.TaggedRoot `json:"roots"`
				}
				if err := json.Unmarshal(data, &rf); err != nil {
					return fmt.Errorf("decode roots file: %w", err)
				}
				if st.Roots == nil {
					st.Roots = make(map[string]rootInfo, len(rf.Roots))
				}
				for _, tr := range rf.Roots {
					st.Roots[tr.Root] = rootInfo{BlockIDs: tr.BlockIDs, BlockCount: tr.BlockCount}
				}
				fmt.Printf("imported roots  count=%d\n", len(rf.Roots))
			}

			st.Pending = nil
			saveState(st)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", `path to an exported key file (dashboard's "Export key file")`)
	cmd.Flags().StringVar(&rootsFile, "roots-file", "", `path to an exported roots file (dashboard's "Export roots")`)
	return cmd
}

func challengeCmd() *cobra.Command {
	var roots []string
	var all bool
	var chalSize int

	cmd := &cobra.Command{
		Use:   "challenge",
		Short: "Build a challenge from local state and save it as pending",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			if st.KeyID == "" {
				return fmt.Errorf("no key in state: run key-create or setup first")
			}
			if len(st.Roots) == 0 {
				return fmt.Errorf("no tagged roots in state: run tag or setup first")
			}

			targetRoots := targetRoots(st, roots, all)
			if len(targetRoots) == 0 {
				return fmt.Errorf("specify --root or --all")
			}

			combinedIDs, err := proverclient.BuildCombinedIDs(stateToSetup(st), targetRoots)
			if err != nil {
				return err
			}

			spec, ok := proverclient.SchemeByProtocol(st.Protocol)
			if !ok {
				return fmt.Errorf("unknown protocol %q", st.Protocol)
			}
			challenger, err := spec.ChalFactory.NewChallenger(st.ClientSetup, chalSize)
			if err != nil {
				return fmt.Errorf("new challenger: %w", err)
			}
			chal, _, err := challenger.Challenge(combinedIDs)
			if err != nil {
				return fmt.Errorf("generate challenge: %w", err)
			}

			st.Pending = &pendingState{Challenge: chal, Roots: targetRoots}
			saveState(st)
			fmt.Printf("challenge generated  roots=%d  blocks=%d  bytes=%d\n",
				len(targetRoots), len(combinedIDs), len(chal))
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&roots, "root", nil, "root CID to include (repeatable)")
	cmd.Flags().BoolVar(&all, "all", false, "include all tagged roots")
	cmd.Flags().IntVar(&chalSize, "challenge-size", 20, "blocks sampled per challenge round")
	return cmd
}

func proveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "prove",
		Short: "Send the pending challenge to the server and save the proof",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			if st.Pending == nil || len(st.Pending.Challenge) == 0 {
				return fmt.Errorf("no pending challenge: run challenge first")
			}

			proof, err := client().Prove(cmd.Context(), st.KeyID, st.Pending.Roots, st.Pending.Challenge, "", nil)
			if err != nil {
				return err
			}

			st.Pending.Proof = proof
			saveState(st)
			fmt.Printf("proof received  bytes=%d\n", len(proof))
			return nil
		},
	}
}

func verifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the pending proof locally",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			if st.Pending == nil || len(st.Pending.Proof) == 0 {
				return fmt.Errorf("no pending proof: run prove first")
			}

			combinedIDs, err := proverclient.BuildCombinedIDs(stateToSetup(st), st.Pending.Roots)
			if err != nil {
				return err
			}

			spec, ok := proverclient.SchemeByProtocol(st.Protocol)
			if !ok {
				return fmt.Errorf("unknown protocol %q", st.Protocol)
			}
			challenger, err := spec.ChalFactory.NewChallenger(st.ClientSetup, 0)
			if err != nil {
				return fmt.Errorf("new challenger: %w", err)
			}
			_, validator, err := challenger.Challenge(combinedIDs)
			if err != nil {
				return fmt.Errorf("recreate challenge: %w", err)
			}
			ok2, err := validator.Verify(st.Pending.Challenge, st.Pending.Proof)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			if ok2 {
				fmt.Println("PASS")
			} else {
				fmt.Fprintln(os.Stderr, "FAIL")
				os.Exit(1)
			}
			return nil
		},
	}
}

func auditCmd() *cobra.Command {
	var roots []string
	var all bool
	var loop bool
	var interval time.Duration
	var chalSize int

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "challenge → prove → verify in one step",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			if st.KeyID == "" {
				return fmt.Errorf("no key in state: run key-create or setup first")
			}
			if len(st.Roots) == 0 {
				return fmt.Errorf("no tagged roots: run tag or setup first")
			}

			targetRoots := targetRoots(st, roots, all)
			if len(targetRoots) == 0 {
				return fmt.Errorf("specify --root or --all")
			}

			keyShort := st.KeyID
			if len(keyShort) > 8 {
				keyShort = keyShort[:8]
			}
			setup := stateToSetup(st)
			c := client()

			for {
				ts := time.Now().UTC().Format(time.RFC3339)

				result, err := c.Audit(cmd.Context(), st.KeyID, setup, st.Protocol, &proverclient.AuditOptions{
					Roots:         targetRoots,
					ChallengeSize: chalSize,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s  ERROR  %v\n", ts, err)
					if !loop {
						os.Exit(1)
					}
				} else if result.Pass {
					fmt.Printf("%s  PASS  roots=%d  blocks=%d  key=%s\n", ts, len(targetRoots), result.BlocksChecked, keyShort)
				} else {
					fmt.Fprintf(os.Stderr, "%s  FAIL  roots=%d  blocks=%d  key=%s\n", ts, len(targetRoots), result.BlocksChecked, keyShort)
					if !loop {
						os.Exit(1)
					}
				}

				if !loop {
					break
				}
				time.Sleep(interval)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&roots, "root", nil, "root CID to audit (repeatable)")
	cmd.Flags().BoolVar(&all, "all", false, "audit all tagged roots")
	cmd.Flags().BoolVar(&loop, "loop", false, "run continuously until interrupted")
	cmd.Flags().DurationVar(&interval, "interval", time.Minute, "sleep between rounds when --loop is set")
	cmd.Flags().IntVar(&chalSize, "challenge-size", 20, "blocks sampled per challenge round")
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Pretty-print the current state file",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := loadState()
			out, err := json.MarshalIndent(st, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(out))
			return nil
		},
	}
}

// --- Shared helpers ---

// targetRoots resolves the --root/--all flags against the roots this client
// has tagged locally.
func targetRoots(st clientState, roots []string, all bool) []string {
	if all {
		out := make([]string, 0, len(st.Roots))
		for r := range st.Roots {
			out = append(out, r)
		}
		return out
	}
	return roots
}

// stateToSetup adapts the local state file's roots map into the
// proverclient.SetupResponse shape BuildCombinedIDs/Audit expect.
func stateToSetup(st clientState) *proverclient.SetupResponse {
	setup := &proverclient.SetupResponse{ClientSetup: st.ClientSetup}
	for root, info := range st.Roots {
		setup.Roots = append(setup.Roots, proverclient.TaggedRoot{
			Root:       root,
			BlockIDs:   info.BlockIDs,
			BlockCount: info.BlockCount,
		})
	}
	return setup
}

// --- State file helpers ---

func stateFile() string { return viper.GetString(flagState) }

func loadState() clientState {
	data, err := os.ReadFile(stateFile())
	if err != nil {
		return clientState{Server: apiBase(), Roots: make(map[string]rootInfo)}
	}
	var st clientState
	if err := json.Unmarshal(data, &st); err != nil {
		fmt.Fprintf(os.Stderr, "warn: corrupt state file, starting fresh: %v\n", err)
		return clientState{Server: apiBase(), Roots: make(map[string]rootInfo)}
	}
	if st.Roots == nil {
		st.Roots = make(map[string]rootInfo)
	}
	return st
}

func saveState(st clientState) {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal state: %v\n", err)
		return
	}
	if err := os.WriteFile(stateFile(), data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write state file: %v\n", err)
	}
}

func apiBase() string { return viper.GetString(flagBaseURL) }

func client() *proverclient.Client {
	return proverclient.NewClient(apiBase())
}
