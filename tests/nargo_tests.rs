use std::{
    fs,
    io::Result,
    path::PathBuf,
    process::{Command, Output},
};

fn configure_test_dirs() -> Vec<PathBuf> {
    let test_dirs_names = vec![
        "1_mul",
        "2_div",
        "3_add",
        "4_sub",
        "5_over",
        "6_array",
        "7_function",
        "bit_and",
    ];
    test_dirs_names
        .into_iter()
        .map(test_program_dir_path)
        .collect()
}

fn nargo_cmd() -> std::process::Command {
    Command::new("nargo")
}

fn nargo_execute(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("execute")
        .spawn()
        .unwrap()
        .wait_with_output()
}

fn nargo_test(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("test")
        .spawn()
        .unwrap()
        .wait_with_output()
}

fn nargo_check(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("check")
        .spawn()
        .unwrap()
        .wait_with_output()
}

fn nargo_gates(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("gates")
        .spawn()
        .unwrap()
        .wait_with_output()
}

fn nargo_compile(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("compile")
        .arg("my_test_circuit")
        .spawn()
        .unwrap()
        .wait_with_output()
}

fn nargo_prove(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("prove")
        .arg("my_test_proof")
        .arg("my_test_circuit")
        .spawn()
        .unwrap()
        .wait_with_output()
}

fn nargo_verify(test_program_dir: &PathBuf) -> Result<Output> {
    nargo_cmd()
        .current_dir(test_program_dir)
        .arg("verify")
        .arg("my_test_proof")
        .arg("my_test_circuit")
        .spawn()
        .unwrap()
        .wait_with_output()
}

pub(crate) fn test_program_dir_path(dir_name: &str) -> PathBuf {
    fs::canonicalize(PathBuf::from(format!("./tests/test_programs/{dir_name}"))).unwrap()
}

pub(crate) fn assert_nargo_cmd_works(cmd_name: &str, test_test_program_dir: &PathBuf) {
    let cmd_output = match cmd_name {
        "check" => nargo_check(test_test_program_dir),
        "contract" => todo!(),
        "compile" => nargo_compile(test_test_program_dir),
        "new" => panic!("This cmd doesn't depend on the backend"),
        "execute" => nargo_execute(test_test_program_dir),
        "prove" => nargo_prove(test_test_program_dir),
        "verify" => nargo_verify(test_test_program_dir),
        "test" => nargo_test(test_test_program_dir),
        "gates" => nargo_gates(test_test_program_dir),
        e => panic!("{e} is not a valid nargo cmd"),
    }
    .unwrap();

    assert!(
        cmd_output.status.success(),
        "stderr(nargo {cmd_name}) in {}: {}",
        test_test_program_dir.display(),
        String::from_utf8(cmd_output.stderr).unwrap()
    );
}

pub fn install_nargo(backend: &'static str) {
    // Clone noir into repo
    Command::new("git")
        .arg("clone")
        .arg("https://github.com/Ethan-000/noir")
        .arg("--branch")
        .arg("add_halo2_backend")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    format!("\nInstalling {backend}. This may take a few moments.",);
    // Install specified backend into noir
    Command::new("cargo")
        .current_dir(fs::canonicalize("./noir/crates/nargo_cli").unwrap())
        .arg("install")
        .arg("--path")
        .arg(".")
        .arg("--locked")
        .arg("--features")
        .arg(backend)
        .arg("--no-default-features")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}

pub(crate) fn run_nargo_tests(test_program: PathBuf) {
    assert_nargo_cmd_works("check", &test_program);
    assert_nargo_cmd_works("compile", &test_program);
    assert_nargo_cmd_works("execute", &test_program);
    assert_nargo_cmd_works("prove", &test_program);
    assert_nargo_cmd_works("verify", &test_program);
    assert_nargo_cmd_works("test", &test_program);
    assert_nargo_cmd_works("gates", &test_program);
}

// TODO: Axiom is currently not working.
// tho tests passes the crs size does not
// change with each test.
#[test]
fn test_axiom_backend() {
    let test_program_dirs = configure_test_dirs();
    // Pass in Axiom Halo2 Backend as argument
    install_nargo("axiom_halo2_backend");
    for test_program in test_program_dirs {
        run_nargo_tests(test_program);
    }
}

#[test]
fn test_pse_backend() {
    let test_program_dirs = configure_test_dirs();
    // Pass in PSE Halo2 Backend as argument
    install_nargo("pse_halo2_backend");
    for test_program in test_program_dirs {
        run_nargo_tests(test_program);
    }
}
