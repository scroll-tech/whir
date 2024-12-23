use std::{
    fs::OpenOptions,
    time::{Duration, Instant},
};

use ark_ff::{FftField, Field};
use ark_serialize::CanonicalSerialize;
use nimue::{DefaultHash, IOPattern};
use whir::{
    cmdline_utils::AvailableFields,
    crypto::{fields, merkle_tree::HashCounter},
    parameters::*,
    poly_utils::coeffs::CoefficientList,
    whir::Statement,
};

use serde::Serialize;

use clap::Parser;
use whir::ceno_binding::{pcs::Whir, PolynomialCommitmentScheme};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'l', long, default_value = "100")]
    security_level: usize,

    #[arg(short = 'p', long)]
    pow_bits: Option<usize>,

    #[arg(short = 'd', long, default_value = "20")]
    num_variables: usize,

    #[arg(short = 'p', long = "num_polys", default_value = "1")]
    num_polys: usize,

    #[arg(short = 'r', long, default_value = "1")]
    rate: usize,

    #[arg(long = "reps", default_value = "1000")]
    verifier_repetitions: usize,

    #[arg(short = 'k', long = "fold", default_value = "4")]
    folding_factor: usize,

    #[arg(long = "sec", default_value = "ConjectureList")]
    soundness_type: SoundnessType,

    #[arg(long = "fold_type", default_value = "ProverHelps")]
    fold_optimisation: FoldType,

    #[arg(short = 'f', long = "field", default_value = "Goldilocks2")]
    field: AvailableFields,
}

#[derive(Debug, Serialize)]
struct BenchmarkOutput {
    security_level: usize,
    pow_bits: usize,
    starting_rate: usize,
    num_variables: usize,
    num_polys: usize,
    repetitions: usize,
    folding_factor: usize,
    soundness_type: SoundnessType,
    field: AvailableFields,

    // Whir
    whir_argument_size: usize,
    whir_prover_time: Duration,
    whir_prover_hashes: usize,
    whir_verifier_time: Duration,
    whir_verifier_hashes: usize,
}

fn main() {
    let mut args = Args::parse();
    let field = args.field;
    if args.pow_bits.is_none() {
        args.pow_bits = Some(default_max_pow(args.num_variables, args.rate));
    }
    match field {
        AvailableFields::Goldilocks1 => {
            use fields::Field64 as F;
            run_whir::<F>(args)
        }
        AvailableFields::Goldilocks2 => {
            use fields::Field64_2 as F;
            run_whir::<F>(args)
        }
        AvailableFields::Goldilocks3 => {
            use fields::Field64_3 as F;
            run_whir::<F>(args)
        }
        AvailableFields::Field128 => {
            use fields::Field128 as F;
            run_whir::<F>(args)
        }
        AvailableFields::Field192 => {
            use fields::Field192 as F;
            run_whir::<F>(args)
        }
        AvailableFields::Field256 => {
            use fields::Field256 as F;
            run_whir::<F>(args)
        }
    }
}

fn run_whir<F>(args: Args)
where
    F: FftField + CanonicalSerialize,
{
    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let num_variables = args.num_variables;
    let num_polys = args.num_polys;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;
    let folding_factor = args.folding_factor;
    let soundness_type = args.soundness_type;
    let fold_optimisation = args.fold_optimisation;

    std::fs::create_dir_all("outputs").unwrap();

    let num_coeffs = 1 << num_variables;

    let partial_params = WhirPartialParameters {
        security_level,
        pow_bits,
        folding_factor,
        soundness_type,
        fold_optimisation,
        starting_log_inv_rate: starting_rate,
    };

    let polynomial = CoefficientList::new(
        (0..num_coeffs)
            .map(<F as Field>::BasePrimeField::from)
            .collect(),
    );

    let (
        whir_prover_time,
        whir_argument_size,
        whir_prover_hashes,
        whir_verifier_time,
        whir_verifier_hashes,
    ) = {
        // Run PCS
        use rand::prelude::*;
        use whir::poly_utils::MultilinearPoint;
        use whir::whir::{iopattern::WhirIOPattern, verifier::Verifier, whir_proof_size};

        let pp = Whir::<F>::setup(num_variables, num_polys, Some(partial_params));
        if !pp.check_pow_bits() {
            println!("WARN: more PoW bits required than what specified.");
        }

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&pp)
            .add_whir_proof(&pp);
        let mut merlin = io.to_merlin();

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..num_variables)
            .map(|_| F::from(rng.gen::<u64>()))
            .collect();
        let eval = polynomial.evaluate_at_extension(&MultilinearPoint(point.clone()));
        let statement = Statement {
            points: vec![MultilinearPoint(point.clone())],
            evaluations: vec![eval],
        };

        HashCounter::reset();
        let whir_prover_time = Instant::now();

        let witness = Whir::<F>::commit_and_write(&pp, &polynomial, &mut merlin).unwrap();
        let proof = Whir::<F>::open(&pp, witness, &point, &eval, &mut merlin).unwrap();

        let whir_prover_time = whir_prover_time.elapsed();
        let whir_argument_size = whir_proof_size(merlin.transcript(), &proof);
        let whir_prover_hashes = HashCounter::get();

        // Just not to count that initial inversion (which could be precomputed)
        let verifier = Verifier::new(pp);

        HashCounter::reset();
        let whir_verifier_time = Instant::now();
        for _ in 0..reps {
            let mut arthur = io.to_arthur(merlin.transcript());
            verifier.verify(&mut arthur, &statement, &proof).unwrap();
        }

        let whir_verifier_time = whir_verifier_time.elapsed();
        let whir_verifier_hashes = HashCounter::get() / reps;

        (
            whir_prover_time,
            whir_argument_size,
            whir_prover_hashes,
            whir_verifier_time,
            whir_verifier_hashes,
        )
    };

    let output = BenchmarkOutput {
        security_level,
        pow_bits,
        starting_rate,
        num_variables,
        num_polys,
        repetitions: reps,
        folding_factor,
        soundness_type,
        field: args.field,

        // Whir
        whir_prover_time,
        whir_argument_size,
        whir_prover_hashes,
        whir_verifier_time,
        whir_verifier_hashes,
    };

    let mut out_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("outputs/bench_output.json")
        .unwrap();
    use std::io::Write;
    writeln!(out_file, "{}", serde_json::to_string(&output).unwrap()).unwrap();
}
