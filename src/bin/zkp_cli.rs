//! zkp_cli — Complete Command-line interface for V2V ZKP operations.
//!
//! Usage:
//!   zkp_cli commit-consumer   --cid 1 --req 30.0 --soc 15.0 --cap 75.0
//!   zkp_cli commit-provider   --pid 10 --avail 50.0 --price 15.0 --min-price 8.0
//!   zkp_cli prove-sufficiency --pid 10 --cid 1 --avail 50.0 --req 30.0
//!   zkp_cli prove-profit      --pid 10 --cid 1 --profit 85.0 --margin 30.0
//!   zkp_cli prove-comparison  --pid 10 --cid 1 --utility-a 1000 --utility-b 800 [--circuit-dir circuits/build]
//!   zkp_cli prove-sum         --actor coordinator --values 100,250,150
//!   zkp_cli verify            --proof-type consumer|provider|sufficiency|profit|comparison|sum [--file proof.json] [--circuit-dir circuits/build]
//!   zkp_cli audit             [--actor consumer_1] [--db zkp_audit.db]
//!   zkp_cli verify-ledger     [--db zkp_audit.db]

use std::io::Read;
use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};
use num_bigint::BigUint;

use zkp_v2v::group::PedersenCommitment;
use zkp_v2v::ledger::AuditLedger;
use zkp_v2v::privacy::{
    consumer_commit, provider_commit, prove_profit_above_margin, prove_sufficient_energy,
    verify_consumer_commitment, verify_profit, verify_provider_commitment, verify_sufficiency,
    ConsumerProofPackage, ProfitProof, ProviderProofPackage, SufficiencyProof,
};
use zkp_v2v::proofs::{zkpsum_prove, zkpsum_verify, ZkpSumProof};
use zkp_v2v::snark::{ComparisonProof, SnarkProver};

#[derive(Parser)]
#[command(name = "zkp_cli")]
#[command(about = "Privacy-preserving V2V energy sharing ZKP tool")]
struct Cli {
    /// Path to the tamper-evident SQLite audit ledger
    #[arg(long, default_value = "zkp_audit.db")]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Commit a consumer's private data (PATCH-2)
    CommitConsumer {
        #[arg(long)]
        cid: u64,
        #[arg(long)]
        req: f64,
        #[arg(long)]
        soc: f64,
        #[arg(long)]
        cap: f64,
    },

    /// Commit a provider's private data (PATCH-3)
    CommitProvider {
        #[arg(long)]
        pid: u64,
        #[arg(long)]
        avail: f64,
        #[arg(long)]
        price: f64,
        #[arg(long, default_value = "8.0")]
        min_price: f64,
    },

    /// Prove sufficient energy for a match (PATCH-5)
    ProveSufficiency {
        #[arg(long)]
        pid: u64,
        #[arg(long)]
        cid: u64,
        #[arg(long)]
        avail: f64,
        #[arg(long)]
        req: f64,
    },

    /// Prove profit above minimum margin (PATCH-4)
    ProveProfit {
        #[arg(long)]
        pid: u64,
        #[arg(long)]
        cid: u64,
        #[arg(long)]
        profit: f64,
        #[arg(long, default_value = "30.0")]
        margin: f64,
    },

    /// Prove private 64-bit utility preference utility_a > utility_b via BN254 Groth16 zkSNARK
    ProveComparison {
        #[arg(long)]
        pid: u64,
        #[arg(long)]
        cid: u64,
        #[arg(long)]
        utility_a: u64,
        #[arg(long)]
        utility_b: u64,
        #[arg(long, default_value = "circuits/build")]
        circuit_dir: String,
    },

    /// Prove homomorphic conservation sum over comma-separated integer values via ZkpSum
    ProveSum {
        #[arg(long, default_value = "coordinator")]
        actor: String,
        /// Comma-separated non-negative integer values (e.g. "100,250,150")
        #[arg(long)]
        values: String,
    },

    /// Verify a proof from JSON (reads from --file or stdin) and log outcome
    Verify {
        /// Proof type: consumer, provider, sufficiency, profit, comparison, sum
        #[arg(long)]
        proof_type: String,
        /// JSON file path (omit to read from stdin)
        #[arg(long)]
        file: Option<String>,
        /// Circuit build directory (used when --proof-type comparison)
        #[arg(long, default_value = "circuits/build")]
        circuit_dir: String,
    },

    /// Query the hash-chained audit ledger
    Audit {
        #[arg(long)]
        actor: Option<String>,
    },

    /// Verify SHA-256 hash-chain integrity of the entire SQLite audit ledger
    VerifyLedger,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let pc = PedersenCommitment::new();

    match cli.command {
        Commands::CommitConsumer { cid, req, soc, cap } => {
            let pkg = consumer_commit(&pc, cid, req, soc, cap)?;
            let json =
                serde_json::to_string_pretty(&pkg).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);

            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&pkg).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(&format!("consumer_{}", cid), "commit_consumer", &compact)?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::CommitProvider {
            pid,
            avail,
            price,
            min_price,
        } => {
            let pkg = provider_commit(&pc, pid, avail, price, min_price)?;
            let json =
                serde_json::to_string_pretty(&pkg).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);

            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&pkg).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(&format!("provider_{}", pid), "commit_provider", &compact)?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::ProveSufficiency {
            pid,
            cid,
            avail,
            req,
        } => {
            let proof = prove_sufficient_energy(&pc, pid, cid, avail, req)
                .ok_or_else(|| "Insufficient energy: avail < req".to_string())?;
            let json =
                serde_json::to_string_pretty(&proof).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);

            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&proof).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(&format!("provider_{}", pid), "prove_sufficiency", &compact)?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::ProveProfit {
            pid,
            cid,
            profit,
            margin,
        } => {
            let proof = prove_profit_above_margin(&pc, pid, cid, profit, margin)
                .ok_or_else(|| "Profit below margin".to_string())?;
            let json =
                serde_json::to_string_pretty(&proof).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);

            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&proof).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(&format!("provider_{}", pid), "prove_profit", &compact)?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::ProveComparison {
            pid,
            cid,
            utility_a,
            utility_b,
            circuit_dir,
        } => {
            let prover = SnarkProver::new(Path::new(&circuit_dir))?;
            let proof = prover.prove_comparison(pid, cid, utility_a, utility_b)?;
            let json =
                serde_json::to_string_pretty(&proof).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);

            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&proof).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(&format!("provider_{}", pid), "prove_comparison", &compact)?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::ProveSum { actor, values } => {
            let parsed_vals: Result<Vec<BigUint>, String> = values
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<u64>()
                        .map(BigUint::from)
                        .map_err(|_| format!("Invalid integer value '{}'", s))
                })
                .collect();
            let vals = parsed_vals?;
            let rs: Vec<BigUint> = vals.iter().map(|_| pc.rand_zq()).collect();
            let proof = zkpsum_prove(&pc, &vals, &rs)?;
            let json =
                serde_json::to_string_pretty(&proof).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);

            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&proof).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(&actor, "prove_sum", &compact)?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::Verify {
            proof_type,
            file,
            circuit_dir,
        } => {
            let json_str = match file {
                Some(path) => std::fs::read_to_string(&path)
                    .map_err(|e| format!("Cannot read {}: {}", path, e))?,
                None => {
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .map_err(|e| format!("stdin error: {}", e))?;
                    buf
                }
            };

            let valid = match proof_type.as_str() {
                "consumer" => {
                    let pkg: ConsumerProofPackage = serde_json::from_str(&json_str)
                        .map_err(|e| format!("JSON parse error: {}", e))?;
                    verify_consumer_commitment(&pc, &pkg)
                }
                "provider" => {
                    let pkg: ProviderProofPackage = serde_json::from_str(&json_str)
                        .map_err(|e| format!("JSON parse error: {}", e))?;
                    verify_provider_commitment(&pc, &pkg)
                }
                "sufficiency" => {
                    let proof: SufficiencyProof = serde_json::from_str(&json_str)
                        .map_err(|e| format!("JSON parse error: {}", e))?;
                    verify_sufficiency(&pc, &proof)
                }
                "profit" => {
                    let proof: ProfitProof = serde_json::from_str(&json_str)
                        .map_err(|e| format!("JSON parse error: {}", e))?;
                    verify_profit(&pc, &proof)
                }
                "comparison" => {
                    let proof: ComparisonProof = serde_json::from_str(&json_str)
                        .map_err(|e| format!("JSON parse error: {}", e))?;
                    let prover = SnarkProver::new(Path::new(&circuit_dir))?;
                    prover.verify_comparison(&proof)?
                }
                "sum" => {
                    let proof: ZkpSumProof = serde_json::from_str(&json_str)
                        .map_err(|e| format!("JSON parse error: {}", e))?;
                    zkpsum_verify(&pc, &proof)
                }
                other => {
                    return Err(format!(
                        "Unknown proof type '{}'. Expected: consumer, provider, sufficiency, profit, comparison, sum",
                        other
                    ))
                }
            };

            let ledger = AuditLedger::new(&cli.db)?;
            let summary = format!(
                r#"{{"proof_type":"{}","valid":{}}}"#,
                proof_type, valid
            );
            ledger.log_proof("verifier", &format!("verify_{}", proof_type), &summary)?;

            if valid {
                println!("VALID");
            } else {
                println!("INVALID");
                process::exit(1);
            }
        }

        Commands::Audit { actor } => {
            let ledger = AuditLedger::new(&cli.db)?;
            let entries = match actor {
                Some(ref a) => ledger.get_proofs_by_actor(a)?,
                None => ledger.get_all_proofs()?,
            };

            if entries.is_empty() {
                println!("No audit entries found.");
            } else {
                println!(
                    "{:<5} {:<21} {:<15} {:<20} {:<14} {}",
                    "ID", "TIMESTAMP", "ACTOR", "ACTION", "HASH (PREFIX)", "PROOF (BYTES)"
                );
                println!("{}", "-".repeat(92));
                for e in &entries {
                    let prefix: String = e.entry_hash.chars().take(12).collect();
                    println!(
                        "{:<5} {:<21} {:<15} {:<20} {:<14} {} bytes",
                        e.id,
                        e.timestamp,
                        e.actor,
                        e.action,
                        prefix,
                        e.proof_json.len()
                    );
                }
                println!("\nTotal: {} entries", entries.len());
            }
        }

        Commands::VerifyLedger => {
            let ledger = AuditLedger::new(&cli.db)?;
            if ledger.verify_chain()? {
                println!("LEDGER_VALID");
            } else {
                println!("LEDGER_TAMPERED");
                process::exit(1);
            }
        }
    }

    Ok(())
}
