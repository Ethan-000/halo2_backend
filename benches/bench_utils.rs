#![allow(dead_code)]

use std::{
    fs,
    io::Result,
    path::PathBuf,
    process::{Command, Output},
};
pub(crate) const BACKENDS: [&str; 2] = ["axiom_halo2_backend", "pse_halo2_backend"];
pub(crate) const HALO2_BACKEND: &str = BACKENDS[1];

fn nargo_cmd() -> std::process::Command {
    Command::new("nargo")
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
        "compile" => nargo_compile(test_test_program_dir),
        "prove" => nargo_prove(test_test_program_dir),
        "verify" => nargo_verify(test_test_program_dir),
        e => panic!("{e} is not a valid in this context"),
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

pub(crate) fn run_nargo_compile(test_program: PathBuf) {
    assert_nargo_cmd_works("compile", &test_program);
}

pub(crate) fn run_nargo_prove(test_program: PathBuf) {
    assert_nargo_cmd_works("prove", &test_program);
}

pub(crate) fn run_nargo_verify(test_program: PathBuf) {
    assert_nargo_cmd_works("verify", &test_program);
}
