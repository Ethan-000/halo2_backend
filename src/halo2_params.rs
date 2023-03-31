use std::{env, path::PathBuf};

use ark_std::log2;
use halo2_proofs_axiom::{
    arithmetic::g_to_lagrange,
    halo2curves::{
        bn256::{Bn256, Fq, Fq2, G1Affine, G2Affine},
        group::prime::PrimeCurveAffine,
        pairing::Engine,
        CurveAffine,
    },
    poly::kzg::commitment::ParamsKZG,
};

const G1_START: usize = 28;
const G2_START: usize = 28 + (5_040_000 * 64);
const G2_END: usize = G2_START + 128 - 1;

fn transcript_location() -> PathBuf {
    match env::var("BARRETENBERG_TRANSCRIPT") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => dirs::home_dir()
            .unwrap()
            .join("noir_cache")
            .join("ignition")
            .join("transcript00.dat"),
    }
}

fn read_crs(path: PathBuf) -> Vec<u8> {
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            assert!(
                e.kind() != std::io::ErrorKind::PermissionDenied,
                "please run again with appropriate permissions."
            );
            panic!(
                "Could not find file transcript00.dat at location {}.\n Starting Download",
                path.display()
            );
        }
    }
}

pub(crate) fn constuct_halo2_params_from_aztec_crs(num_points: u32) -> ParamsKZG<Bn256> {
    let points_needed = pow2ceil(num_points);
    let g1_end = G1_START + ((points_needed as usize - 1) * 64) - 1;
    // If the CRS does not exist, then download it from S3
    if !transcript_location().exists() {
        download_crs(transcript_location());
    }

    // Read CRS, if it's incomplete, download it
    let mut crs = read_crs(transcript_location());
    if crs.len() < G2_END + 1 {
        download_crs(transcript_location());
        crs = read_crs(transcript_location());
    }

    let g1_data = crs[G1_START..=g1_end].to_vec();
    let g2_data = crs[G2_START..=G2_END].to_vec();

    let k = log2(points_needed as usize);
    let n = points_needed as u64;

    let mut g = vec![<<Bn256 as Engine>::G1Affine as PrimeCurveAffine>::generator()];

    g.extend(g1_data.chunks(64).map(|g1| to_g1_point(g1)));

    let g_lagrange = g_to_lagrange(g.iter().map(|g| PrimeCurveAffine::to_curve(g)).collect(), k);

    let g2 = <<Bn256 as Engine>::G2Affine as PrimeCurveAffine>::generator();
    let s_g2 = to_g2_point(&g2_data);

    // WARNING: currently the fields of ParamsKZG are private
    // and there's no consturctor from these fields,
    // so I changed my local version of these fields to public.
    ParamsKZG::<Bn256> {
        k,
        n,
        g,
        g_lagrange,
        g2,
        s_g2,
    }
}

pub fn download_crs(mut path_to_transcript: PathBuf) {
    // Remove old crs
    if path_to_transcript.exists() {
        let _ = std::fs::remove_file(path_to_transcript.as_path());
    }
    // Pop off the transcript component to get just the directory
    path_to_transcript.pop();

    if !path_to_transcript.exists() {
        std::fs::create_dir_all(&path_to_transcript).unwrap();
    }

    let url = "http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/sealed/transcript00.dat";
    use downloader::Downloader;
    let mut downloader = Downloader::builder()
        .download_folder(path_to_transcript.as_path())
        .build()
        .unwrap();

    let dl = downloader::Download::new(url);
    let dl = dl.progress(SimpleReporter::create());
    let result = downloader.download(&[dl]).unwrap();

    for r in result {
        match r {
            Err(e) => println!("Error: {e}"),
            Ok(s) => println!("\nSRS is located at : {:?}", &s.file_name),
        };
    }
}

// Taken from https://github.com/hunger/downloader/blob/main/examples/download.rs
struct SimpleReporterPrivate {
    started: std::time::Instant,
    progress_bar: indicatif::ProgressBar,
}
struct SimpleReporter {
    private: std::sync::Mutex<Option<SimpleReporterPrivate>>,
}

impl SimpleReporter {
    fn create() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            private: std::sync::Mutex::new(None),
        })
    }
}

impl downloader::progress::Reporter for SimpleReporter {
    fn setup(&self, max_progress: Option<u64>, _message: &str) {
        let bar = indicatif::ProgressBar::new(max_progress.unwrap());
        bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                .progress_chars("##-"),
        );

        let private = SimpleReporterPrivate {
            started: std::time::Instant::now(),
            progress_bar: bar,
        };
        println!("\nDownloading the Ignite SRS (340MB)\n");

        let mut guard = self.private.lock().unwrap();
        *guard = Some(private);
    }

    fn progress(&self, current: u64) {
        if let Some(p) = self.private.lock().unwrap().as_mut() {
            p.progress_bar.set_position(current);
        }
    }

    fn set_message(&self, _message: &str) {}

    fn done(&self) {
        let mut guard = self.private.lock().unwrap();
        let p = guard.as_mut().unwrap();
        p.progress_bar.finish();
        println!("Downloaded the SRS successfully!");
        println!(
            "Time Elapsed: {}",
            indicatif::HumanDuration(p.started.elapsed())
        );
    }
}

fn to_g1_point(point: &[u8]) -> G1Affine {
    let le_bytes: Vec<u8> = point
        .chunks(8)
        .map(|limb| {
            let mut new_limb = limb.to_vec();
            new_limb.reverse();
            new_limb
        })
        .flatten()
        .collect();

    let mut first_byte_array = [0u8; 32];
    let mut second_byte_array = [0u8; 32];

    for i in 0..le_bytes.len() {
        if i < 32 {
            first_byte_array[i] = le_bytes[i]
        } else {
            second_byte_array[i - 32] = le_bytes[i]
        }
    }

    G1Affine::from_xy(
        Fq::from_bytes(&first_byte_array).unwrap(),
        Fq::from_bytes(&second_byte_array).unwrap(),
    )
    .unwrap()
}

fn to_g2_point(point: &[u8]) -> G2Affine {
    let le_bytes: Vec<u8> = point
        .chunks(8)
        .map(|limb| {
            let mut new_limb = limb.to_vec();
            new_limb.reverse();
            new_limb
        })
        .flatten()
        .collect();

    let mut first_byte_array = [0u8; 64];
    let mut second_byte_array = [0u8; 64];

    for i in 0..le_bytes.len() {
        if i < 64 {
            first_byte_array[i] = le_bytes[i]
        } else {
            second_byte_array[i - 64] = le_bytes[i]
        }
    }

    G2Affine::from_xy(
        Fq2::from_bytes(&first_byte_array).unwrap(),
        Fq2::from_bytes(&second_byte_array).unwrap(),
    )
    .unwrap()
}

fn pow2ceil(v: u32) -> u32 {
    v.next_power_of_two()
}
