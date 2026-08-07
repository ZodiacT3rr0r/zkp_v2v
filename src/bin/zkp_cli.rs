//! zkp_cli — Command-line interface for V2V ZKP operations.
//!
//! Usage:
//!   zkp_cli commit-consumer --cid 1 --req 30.0 --soc 15.0 --cap 75.0
//!   zkp_cli commit-provider --pid 10 --avail 50.0 --price 15.0 --min-price 8.0
//!   zkp_cli prove-sufficiency --pid 10 --cid 1 --avail 50.0 --req 30.0
//!   zkp_cli prove-profit --pid 10 --cid 1 --profit 85.0 --margin 30.0
//!   zkp_cli verify --proof-type consumer --file proof.json
//!   zkp_cli audit [--actor consumer_1] [--db zkp_audit.db]
//!
//! All proof commands output JSON to stdout and log to the audit DB.

use std::io::Read;
use std::process;

use clap::{Parser, Subcommand};

use zkp_v2v::group::PedersenCommitment;
use zkp_v2v::ledger::AuditLedger;
use zkp_v2v::privacy::{
    consumer_commit, provider_commit, prove_profit_above_margin, prove_sufficient_energy,
    verify_consumer_commitment, verify_provider_commitment, verify_profit, verify_sufficiency,
    ConsumerProofPackage, ProfitProof, ProviderProofPackage, SufficiencyProof,
};

/// V2V ZKP command-line interface
#[derive(Parser)]
#[command(name = "zkp_cli")]
#[command(about = "Privacy-preserving V2V energy sharing ZKP tool")]
struct Cli {
    /// Path to the audit SQLite database
    #[arg(long, default_value = "zkp_audit.db")]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Commit a consumer's private data (PATCH-2)
    CommitConsumer {
        /// Consumer vehicle ID — Consumers(i, 1)
        #[arg(long)]
        cid: u64,
        /// Required charge in kWh — Consumers(i, 10)
        #[arg(long)]
        req: f64,
        /// Current state of charge in kWh — Consumers(i, 11)
        #[arg(long)]
        soc: f64,
        /// Battery capacity in kWh — Car_Model(Consumers(i,5), 2)
        #[arg(long)]
        cap: f64,
    },

    /// Commit a provider's private data (PATCH-3)
    CommitProvider {
        /// Provider vehicle ID — Providers(k, 1)
        #[arg(long)]
        pid: u64,
        /// Available energy for trading in kWh
        /// (derived as Car_Model(Providers(k,5), 2) * 0.5)
        #[arg(long)]
        avail: f64,
        /// Trading price in cents/kWh — Providers(k, 6)
        #[arg(long)]
        price: f64,
        /// Minimum price (grid cost) in cents/kWh — Po (default: 8.0)
        #[arg(long, default_value = "8.0")]
        min_price: f64,
    },

    /// Prove sufficient energy for a match (PATCH-5)
    ProveSufficiency {
        /// Provider vehicle ID
        #[arg(long)]
        pid: u64,
        /// Consumer vehicle ID
        #[arg(long)]
        cid: u64,
        /// Provider's available energy in kWh
        #[arg(long)]
        avail: f64,
        /// Consumer's required charge in kWh — Consumers(i, 10)
        #[arg(long)]
        req: f64,
    },

    /// Prove profit above minimum margin (PATCH-4)
    ProveProfit {
        /// Provider vehicle ID
        #[arg(long)]
        pid: u64,
        /// Consumer vehicle ID
        #[arg(long)]
        cid: u64,
        /// Profit for this pair in cents — Profit_P{k}(j,i)
        #[arg(long)]
        profit: f64,
        /// Minimum profit margin in cents — ProfitMargin (default: 30.0)
        #[arg(long, default_value = "30.0")]
        margin: f64,
    },

    /// Verify a proof from JSON (reads from --file or stdin)
    Verify {
        /// Proof type: consumer, provider, sufficiency, profit
        #[arg(long)]
        proof_type: String,
        /// JSON file path (omit to read from stdin)
        #[arg(long)]
        file: Option<String>,
    },

    /// Query the audit ledger
    Audit {
        /// Filter by actor name (omit to show all)
        #[arg(long)]
        actor: Option<String>,
    },
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

            // Log to audit ledger
            let ledger = AuditLedger::new(&cli.db)?;
            let compact =
                serde_json::to_string(&pkg).map_err(|e| format!("JSON error: {}", e))?;
            ledger.log_proof(
                &format!("consumer_{}", cid),
                "commit_consumer",
                &compact,
            )?;
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
            ledger.log_proof(
                &format!("provider_{}", pid),
                "commit_provider",
                &compact,
            )?;
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
            ledger.log_proof(
                &format!("provider_{}", pid),
                "prove_sufficiency",
                &compact,
            )?;
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
            ledger.log_proof(
                &format!("provider_{}", pid),
                "prove_profit",
                &compact,
            )?;
            eprintln!("Logged to {}", cli.db);
        }

        Commands::Verify { proof_type, file } => {
            // Read JSON from file or stdin
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
                other => return Err(format!(
                    "Unknown proof type '{}'. Expected: consumer, provider, sufficiency, profit",
                    other
                )),
            };

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
                for entry in &entries {
                    println!(
                        "[{}] id={} actor={} action={}",
                        entry.timestamp, entry.id, entry.actor, entry.action
                    );
                }
                println!("\nTotal: {} entries", entries.len());
            }
        }
    }

    Ok(())
}
