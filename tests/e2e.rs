use std::process::Command;
use std::path::PathBuf;
use std::fs;

#[test]
fn test_cli_help() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let output = Command::new(&bin_path)
        .arg("--help")
        .output()
        .expect("Failed to execute codeaegis help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CodeAegis Local Security Scanner"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("scan"));
}

#[test]
fn test_cli_init() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let target_path = std::env::temp_dir().join(format!("codeaegis-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&target_path).expect("Failed to create temp dir");

    let output = Command::new(&bin_path)
        .arg("init")
        .arg(&target_path)
        .output()
        .expect("Failed to execute codeaegis init");

    assert!(output.status.success());
    
    let skill_md_path = target_path.join(".agent/skills/codeaegis/SKILL.md");
    assert!(skill_md_path.exists());
    
    let content = fs::read_to_string(&skill_md_path).expect("Failed to read SKILL.md");
    assert!(content.contains("name: codeaegis"));
    assert!(content.contains("CodeAegis Security Scanner Skill"));

    let _ = fs::remove_dir_all(target_path);
}

#[test]
fn test_cli_scan_non_recursive() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    
    let output = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .output()
        .expect("Failed to execute codeaegis scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scanning directory: example_code (recursive: false)"));
    assert!(!stdout.contains("subdir/nested.py"));
    assert!(stdout.contains("Scan Summary"));
}

#[test]
fn test_cli_scan_recursive() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    
    let output = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("-r")
        .output()
        .expect("Failed to execute codeaegis scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scanning directory: example_code (recursive: true)"));
    assert!(stdout.contains("subdir/nested.py"));
    assert!(stdout.contains("Scan Summary"));
}

#[test]
fn test_cli_scan_toggle_scanners() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    
    // Test including only opengrep
    let output = Command::new(&bin_path)
        .arg("--scanners")
        .arg("opengrep")
        .arg("scan")
        .arg("example_code")
        .output()
        .expect("Failed to execute codeaegis scan with specific scanners");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan Summary"));

    // Test skipping all scanners
    let output_skip = Command::new(&bin_path)
        .arg("--skip-scanners")
        .arg("trufflehog,trivy,osv,opengrep")
        .arg("scan")
        .arg("example_code")
        .output()
        .expect("Failed to execute codeaegis scan with skipped scanners");

    assert!(output_skip.status.success());
    let stdout_skip = String::from_utf8_lossy(&output_skip.stdout);
    assert!(stdout_skip.contains("Scan Summary"));
}

#[test]
fn test_cli_scan_exclusions() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let exclusions_path = PathBuf::from(".agent/skills/codeaegis/exclusions.json");
    
    // Ensure clean state (no config file)
    let _ = fs::remove_file(&exclusions_path);

    // 1. Exclude clean.py with ALL
    let output_exclude = Command::new(&bin_path)
        .arg("exclude")
        .arg("clean.py")
        .arg("--scanners")
        .arg("all")
        .output()
        .expect("Failed to execute codeaegis exclude");

    assert!(output_exclude.status.success());
    assert!(exclusions_path.exists());

    // 2. Scan and verify clean.py is skipped
    let output_scan = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .output()
        .expect("Failed to execute codeaegis scan");

    assert!(output_scan.status.success());
    let stdout = String::from_utf8_lossy(&output_scan.stdout);
    assert!(stdout.contains("Scanning clean.py... Skipped (Excluded)"));

    // Cleanup
    let _ = fs::remove_file(&exclusions_path);
}

#[test]
fn test_cli_inline_suppression() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let temp_file = PathBuf::from("suppress_test.py");

    // 1. Create file with AWS secret (unignored)
    fs::write(&temp_file, "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n").unwrap();

    let output_detected = Command::new(&bin_path)
        .arg("scan")
        .arg("suppress_test.py")
        .output()
        .expect("Failed to scan file");

    let stdout_detected = String::from_utf8_lossy(&output_detected.stdout);
    let has_findings = stdout_detected.contains("High") || stdout_detected.contains("Critical") || stdout_detected.contains("Medium") || stdout_detected.contains("Low");

    if has_findings {
        // 2. Add same-line ignore comment
        fs::write(&temp_file, "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\" # codeaegis:ignore\n").unwrap();

        let output_ignored = Command::new(&bin_path)
            .arg("scan")
            .arg("suppress_test.py")
            .output()
            .expect("Failed to scan file");

        let stdout_ignored = String::from_utf8_lossy(&output_ignored.stdout);
        assert!(stdout_ignored.contains("None") || !stdout_ignored.contains("High"));

        // 3. Add next-line ignore comment
        fs::write(&temp_file, "# codeaegis:ignore-next-line\nAWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n").unwrap();

        let output_ignored_next = Command::new(&bin_path)
            .arg("scan")
            .arg("suppress_test.py")
            .output()
            .expect("Failed to scan file");

        let stdout_ignored_next = String::from_utf8_lossy(&output_ignored_next.stdout);
        assert!(stdout_ignored_next.contains("None") || !stdout_ignored_next.contains("High"));
    }

    // Cleanup
    let _ = fs::remove_file(&temp_file);
}

#[test]
fn test_cli_persistent_cache() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let cache_file = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".codeaegis-cache.json");

    // Clear existing cache file
    let _ = fs::remove_file(&cache_file);

    // Scan a file to populate cache
    let output = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code/clean.py")
        .output()
        .unwrap();

    assert!(output.status.success());
    // Give it a tiny bit of time to persist asynchronously
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check that cache file exists and has entries
    assert!(cache_file.exists());
    let cache_content = fs::read_to_string(&cache_file).unwrap();
    assert!(cache_content.contains("hash"));
}

#[test]
fn test_cli_cicd_controls() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));

    // 1. Check --format json
    let output_json = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(output_json.status.success());
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    assert!(stdout_json.contains("scanned_directory"));
    assert!(stdout_json.contains("findings_count"));

    // 2. Check severity threshold exit code behavior
    let output_default = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .output()
        .unwrap();

    let stdout_default = String::from_utf8_lossy(&output_default.stdout);
    let has_findings = stdout_default.contains("Critical") || stdout_default.contains("High") || stdout_default.contains("Medium") || stdout_default.contains("Low");

    if has_findings {
        // Assert it fails without --no-fail
        assert!(!output_default.status.success());

        // With --no-fail, it must succeed (exit code 0)
        let output_nofail = Command::new(&bin_path)
            .arg("scan")
            .arg("example_code")
            .arg("--no-fail")
            .output()
            .unwrap();
        assert!(output_nofail.status.success());

        // With --severity-threshold none, it fails since findings exist
        let output_none = Command::new(&bin_path)
            .arg("scan")
            .arg("example_code")
            .arg("--severity-threshold")
            .arg("none")
            .output()
            .unwrap();
        assert!(!output_none.status.success());
    }
}

#[test]
fn test_cli_report_formats() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    
    // Paths for testing reports
    let rep_json = PathBuf::from("test_report.json");
    let rep_xml = PathBuf::from("test_report.xml");
    let rep_md = PathBuf::from("test_report.md");
    let rep_csv = PathBuf::from("test_report.csv");
    let rep_html = PathBuf::from("test_report.html");

    // Clean any remnants
    let _ = fs::remove_file(&rep_json);
    let _ = fs::remove_file(&rep_xml);
    let _ = fs::remove_file(&rep_md);
    let _ = fs::remove_file(&rep_csv);
    let _ = fs::remove_file(&rep_html);

    // 1. Scan and write report formats
    let output = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("--no-fail")
        .arg("--report")
        .arg("test_report.json")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(rep_json.exists());
    let data_json = fs::read_to_string(&rep_json).unwrap();
    assert!(data_json.contains("results"));

    // 2. XML / JUnit test
    let output_xml = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("--no-fail")
        .arg("--report")
        .arg("test_report.xml")
        .output()
        .unwrap();
    assert!(output_xml.status.success());
    assert!(rep_xml.exists());
    let data_xml = fs::read_to_string(&rep_xml).unwrap();
    assert!(data_xml.contains("<?xml"));
    assert!(data_xml.contains("testsuite"));

    // 3. Markdown test
    let output_md = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("--no-fail")
        .arg("--report")
        .arg("test_report.md")
        .output()
        .unwrap();
    assert!(output_md.status.success());
    assert!(rep_md.exists());
    let data_md = fs::read_to_string(&rep_md).unwrap();
    assert!(data_md.contains("#"));

    // 4. CSV test
    let output_csv = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("--no-fail")
        .arg("--report")
        .arg("test_report.csv")
        .output()
        .unwrap();
    assert!(output_csv.status.success());
    assert!(rep_csv.exists());
    let data_csv = fs::read_to_string(&rep_csv).unwrap();
    assert!(data_csv.contains("File"));

    // 5. HTML test
    let output_html = Command::new(&bin_path)
        .arg("scan")
        .arg("example_code")
        .arg("--no-fail")
        .arg("--report")
        .arg("test_report.html")
        .output()
        .unwrap();
    assert!(output_html.status.success());
    assert!(rep_html.exists());
    let data_html = fs::read_to_string(&rep_html).unwrap();
    assert!(data_html.contains("<!DOCTYPE html>"));

    // Clean up
    let _ = fs::remove_file(&rep_json);
    let _ = fs::remove_file(&rep_xml);
    let _ = fs::remove_file(&rep_md);
    let _ = fs::remove_file(&rep_csv);
    let _ = fs::remove_file(&rep_html);
}

#[test]
fn test_cli_init_with_hooks() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let target_path = std::env::temp_dir().join(format!("codeaegis-test-hooks-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&target_path).expect("Failed to create temp dir");

    // Initialize mock git repo
    let git_init_status = Command::new("git")
        .arg("init")
        .arg(&target_path)
        .status()
        .expect("Failed to run git init");
    assert!(git_init_status.success());

    let output = Command::new(&bin_path)
        .arg("init")
        .arg(&target_path)
        .output()
        .expect("Failed to execute codeaegis init");

    assert!(output.status.success());
    
    let skill_md_path = target_path.join(".agent/skills/codeaegis/SKILL.md");
    assert!(skill_md_path.exists());
    
    let hook_path = target_path.join(".git/hooks/pre-commit");
    assert!(hook_path.exists());
    
    let hook_content = fs::read_to_string(&hook_path).unwrap();
    assert!(hook_content.contains("CodeAegis Pre-Commit Security Guard"));

    let _ = fs::remove_dir_all(target_path);
}

#[test]
fn test_cli_init_no_hooks() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let target_path = std::env::temp_dir().join(format!("codeaegis-test-nohooks-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&target_path).expect("Failed to create temp dir");

    // Initialize mock git repo
    let git_init_status = Command::new("git")
        .arg("init")
        .arg(&target_path)
        .status()
        .expect("Failed to run git init");
    assert!(git_init_status.success());

    let output = Command::new(&bin_path)
        .arg("init")
        .arg(&target_path)
        .arg("--no-hooks")
        .output()
        .expect("Failed to execute codeaegis init --no-hooks");

    assert!(output.status.success());
    
    let skill_md_path = target_path.join(".agent/skills/codeaegis/SKILL.md");
    assert!(skill_md_path.exists());
    
    let hook_path = target_path.join(".git/hooks/pre-commit");
    assert!(!hook_path.exists());

    let _ = fs::remove_dir_all(target_path);
}

#[test]
fn test_cli_init_no_git() {
    let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_codeaegis"));
    let target_path = std::env::temp_dir().join(format!("codeaegis-test-nogit-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&target_path).expect("Failed to create temp dir");

    // Run init without .git folder present
    let output = Command::new(&bin_path)
        .arg("init")
        .arg(&target_path)
        .output()
        .expect("Failed to execute codeaegis init");

    assert!(output.status.success());
    
    let skill_md_path = target_path.join(".agent/skills/codeaegis/SKILL.md");
    assert!(skill_md_path.exists());
    
    let hook_path = target_path.join(".git/hooks/pre-commit");
    assert!(!hook_path.exists());

    let _ = fs::remove_dir_all(target_path);
}
