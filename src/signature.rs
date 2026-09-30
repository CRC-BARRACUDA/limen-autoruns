//! Whether the program an autorun points at is signed by somebody.
//!
//! An autorun list is a list of things that will run without being asked. The
//! question a reader has about each one is "should this be here", and a
//! signature is the cheapest evidence there is: a Microsoft-signed service in
//! `System32` is boring, and an unsigned executable in a user's `AppData`
//! folder launched from a `Run` key is where an investigation starts.
//!
//! Checked in **one** call for the whole scan. `Get-AuthenticodeSignature`
//! reads and hashes each file and walks its certificate chain — measured here
//! at ~13 ms per file — so one process per entry would cost several seconds of
//! process startup on top of that, and the paths repeat besides: the same
//! executable is named by several ASEPs.
//!
//! Not on Linux, which has no equivalent to check: a package manager's own
//! verification is a different question, asked of the package rather than of
//! the file, and answering it with an empty column would read as "unsigned".

use std::collections::HashMap;

/// What the signature said, as a fixed word.
///
/// Fixed so the view can act on it *and* say it in the user's language, the
/// same way [`crate::signature::Status`]'s callers treat a licence status: the
/// caller decides colour and wording, this decides fact.
pub const VALID: &str = "valid";
/// Nothing signed it.
pub const UNSIGNED: &str = "unsigned";
/// It is signed and the signature does not hold — tampered, or signed by
/// somebody this machine does not trust.
pub const INVALID: &str = "invalid";
/// The check itself did not answer. Deliberately distinct from `unsigned`: not
/// knowing is not the same as knowing there is nothing, and a row coloured as
/// unsigned on the strength of a failed check is a false accusation.
pub const UNKNOWN: &str = "unknown";
/// The entry names a file that is not on disk.
///
/// Usually leftovers — an uninstaller that tidied the program and not the key.
/// Worth seeing anyway, and worth seeing *separately* from a signature result:
/// an autostart pointing at a path that does not exist **yet** is somewhere an
/// attacker can put a file of their own and have it loaded, which is the whole
/// of phantom DLL hijacking.
pub const MISSING: &str = "missing";

/// Verify every path in one pass. Paths not in the answer are not in the map,
/// and the caller leaves those rows unmarked.
#[cfg(target_os = "windows")]
pub fn verify(paths: &[String]) -> HashMap<String, Signed> {
    // The same executable is named by several ASEPs — `svchost.exe` by a dozen
    // services — so ask about each file once.
    let mut wanted: Vec<&String> = paths.iter().collect();
    wanted.sort();
    wanted.dedup();
    if wanted.is_empty() {
        return HashMap::new();
    }

    // Verifying a file reads it, hashes it and walks a certificate chain —
    // about 12ms each, and the dominant cost of a scan by a wide margin. The
    // files are independent of one another, so the list is cut into as many
    // pieces as there are cores and each is asked about by a process of its
    // own. One process per *file* would not do: PowerShell costs ~200ms to
    // start, which is fifteen files' worth of work.
    let workers = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .clamp(1, 8)
        // No point starting a worker for a handful of files.
        .min(wanted.len().div_ceil(24).max(1));
    if workers <= 1 {
        return verify_chunk(0, &wanted);
    }
    let per = wanted.len().div_ceil(workers);
    let mut out = HashMap::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = wanted
            .chunks(per)
            .enumerate()
            .map(|(i, chunk)| s.spawn(move || verify_chunk(i, chunk)))
            .collect();
        for h in handles {
            // A worker that panicked costs its own slice and nothing else: the
            // rows it would have answered for are simply left unmarked.
            if let Ok(part) = h.join() {
                out.extend(part);
            }
        }
    });
    out
}

/// One worker's share of the list, asked about in a process of its own.
#[cfg(target_os = "windows")]
fn verify_chunk(worker: usize, wanted: &[&String]) -> HashMap<String, Signed> {
    use limen_proto::NoConsole;

    let mut out = HashMap::new();
    if wanted.is_empty() {
        return out;
    }

    // The list goes in a file rather than on the command line. A machine with a
    // few hundred autoruns produces tens of kilobytes of paths, and Windows
    // cuts a command line off at about 32k — silently, mid-path, which would
    // show up as a handful of rows inexplicably unchecked.
    // One file per worker, or they would overwrite each other's list.
    let list = std::env::temp_dir()
        .join(format!("limen-autoruns-{}-{worker}.txt", std::process::id()));
    if std::fs::write(&list, wanted.iter().fold(String::new(), |mut s, p| {
        s.push_str(p);
        s.push('\n');
        s
    }))
    .is_err()
    {
        return out;
    }

    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let shell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    // `status|signer|path` a line, the path last so one containing `|` cannot
    // be read as a field break. Every file is asked about individually inside
    // the one process: a batch call drops out entirely on the first path it
    // dislikes, and one bad path must not cost the other three hundred their
    // answer.
    //
    // The signer's common name, not the whole certificate subject: `CN=Igor
    // Pavlov, O=Igor Pavlov, L=…, C=RU` is not a publisher a person reads.
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue';\
         foreach($p in [IO.File]::ReadAllLines('{list}')){{\
           if(-not $p){{continue}};\
           $s=$null;$s=Get-AuthenticodeSignature -LiteralPath $p;\
           $st=if($s){{[string]$s.Status}}else{{'UnknownError'}};\
           $who='';\
           if($s -and $s.SignerCertificate){{\
             $who=[string]$s.SignerCertificate.GetNameInfo('SimpleName',$false)\
           }};\
           $who=($who -replace '[\\r\\n\\|]',' ').Trim();\
           $kind='';if($s){{$kind=[string]$s.SignatureType}};\
           Write-Output ($st + '|' + $kind + '|' + $who + '|' + $p)\
         }}",
        list = list.to_string_lossy().replace('\'', "''")
    );

    let run = std::process::Command::new(shell)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .no_console()
        .output();
    let _ = std::fs::remove_file(&list);

    let Ok(run) = run else {
        return out;
    };
    for line in String::from_utf8_lossy(&run.stdout).lines() {
        // Split from the left a field at a time, so a path containing `|`
        // arrives whole — it is last for exactly that reason.
        let mut it = line.trim_end().splitn(4, '|');
        let (Some(status), Some(kind), Some(signer), Some(path)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let signer = signer.trim();
        out.insert(
            path.to_string(),
            Signed {
                status: classify(status.trim(), signer).to_string(),
                signer: signer.to_string(),
                kind: kind_word(kind.trim()).to_string(),
            },
        );
    }
    out
}

/// What a file's signature says: whether it holds, and who signed it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signed {
    /// One of [`VALID`], [`UNSIGNED`], [`INVALID`], [`UNKNOWN`].
    pub status: String,
    /// The signer's common name, empty when nothing signed it.
    pub signer: String,
    /// Where the signature is: `embedded` in the file, or in a `catalog` the
    /// operating system keeps. Empty when there is none.
    ///
    /// Worth recording because it explains a disagreement a user will meet:
    /// Sysinternals Autoruns reports a catalog-signed file as *not verified*,
    /// looking only inside the file. Most of Windows is signed this way, and
    /// the catalog is what Windows itself trusts those files by — so a scan
    /// that called them unverified would cry wolf on the whole operating
    /// system.
    pub kind: String,
}

/// `SignatureType` as PowerShell names it.
fn kind_word(kind: &str) -> &'static str {
    match kind {
        "Catalog" => "catalog",
        "Embedded" => "embedded",
        _ => "",
    }
}

impl Signed {
    /// The publisher as a reader sees it: the signer, with whether the
    /// signature holds in front of it.
    ///
    /// Both halves together, the way Sysinternals Autoruns puts it, because
    /// either alone misleads. A name on its own reads as an assurance — plenty
    /// of malware is signed, and some of it with a stolen certificate that no
    /// longer verifies. "Not verified" on its own throws away the one clue
    /// worth having, which is who claims to have made the thing.
    pub fn publisher(&self, verified: &str, not_verified: &str, not_checked: &str) -> String {
        if self.status.is_empty() {
            return String::new();
        }
        // Three words for three states, because the colour alone does not say
        // which: a yellow row reading "(Not verified)" is indistinguishable
        // from a red one, and they mean different things — one is a signature
        // that failed, the other a check that never answered.
        let mark = match self.status.as_str() {
            VALID => verified,
            UNKNOWN => not_checked,
            _ => not_verified,
        };
        if self.signer.is_empty() {
            mark.to_string()
        } else {
            format!("{mark} {}", self.signer)
        }
    }
}

/// Off Windows there is nothing to verify this way. An empty map leaves every
/// row unmarked, which is what a machine with no Authenticode should show.
#[cfg(not(target_os = "windows"))]
pub fn verify(_paths: &[String]) -> HashMap<String, Signed> {
    HashMap::new()
}

/// What a file's signature amounts to, from the status and who signed it.
///
/// `Get-AuthenticodeSignature` reports an untrusted certificate chain as
/// `UnknownError` rather than `NotTrusted`, with the reason only in the status
/// *message*: virtio-win's `blnsvr.exe` comes back `UnknownError` — "terminated
/// in a root certificate which is not trusted" — for a binary signed by
/// `CN=Red Hat Inc., OU=Dev` with its own root.
///
/// The signer is what tells the two apart. If a certificate was read, the check
/// ran and the signature did not stand up: that is a finding, not an absence of
/// one. With no certificate to read, the check genuinely did not answer.
fn classify(status: &str, signer: &str) -> &'static str {
    match status_word(status) {
        UNKNOWN if !signer.is_empty() => INVALID,
        word => word,
    }
}

/// `SignatureStatus` as PowerShell names it, reduced to what a reader needs.
///
/// `NotSigned` and `HashMismatch` are told apart because the difference is the
/// whole point: plenty of legitimate software is unsigned, and almost nothing
/// legitimate has a signature that fails to match its own bytes.
fn status_word(status: &str) -> &'static str {
    match status {
        "Valid" => VALID,
        "NotSigned" => UNSIGNED,
        // Signed, but the signature does not stand up: altered since signing,
        // or a chain this machine will not trust.
        "HashMismatch" | "NotTrusted" | "NotSupportedFileFormat" => INVALID,
        // "UnknownError", "Incompatible", and anything a later Windows adds.
        _ => UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every status PowerShell documents maps to one of the four words, and the
    /// two that matter are kept apart.
    #[test]
    fn a_status_becomes_one_of_four_words() {
        assert_eq!(status_word("Valid"), VALID);
        assert_eq!(status_word("NotSigned"), UNSIGNED);
        assert_eq!(status_word("HashMismatch"), INVALID);
        assert_eq!(status_word("NotTrusted"), INVALID);
        // Unsigned and tampered are not the same finding, and must not collapse
        // into one another: plenty of honest software is unsigned, and almost
        // nothing honest fails its own hash.
        assert_ne!(status_word("NotSigned"), status_word("HashMismatch"));
    }

    /// An untrusted certificate chain is a finding, not an absence of one.
    ///
    /// PowerShell reports it as `UnknownError` with the reason only in the
    /// status message — virtio-win's blnsvr.exe, signed by `CN=Red Hat Inc.,
    /// OU=Dev` with its own root, comes back exactly so. Having read a signer
    /// means the check ran and the signature did not stand up.
    #[test]
    fn a_signature_that_did_not_stand_up_is_not_a_check_that_did_not_run() {
        assert_eq!(classify("UnknownError", "Red Hat Inc."), INVALID);
        // With nothing read, the check genuinely did not answer.
        assert_eq!(classify("UnknownError", ""), UNKNOWN);
        // And a clear answer is never second-guessed by the signer.
        assert_eq!(classify("Valid", "Microsoft Windows"), VALID);
        assert_eq!(classify("NotSigned", ""), UNSIGNED);
        assert_eq!(classify("HashMismatch", "Somebody"), INVALID);
    }

    /// A word this build has never heard of is `unknown`, not `unsigned`.
    /// Colouring a row as unsigned because the check did not answer would be an
    /// accusation made out of ignorance.
    #[test]
    fn an_unrecognised_status_admits_it_does_not_know() {
        for odd in ["UnknownError", "Incompatible", "SomethingNew", ""] {
            assert_eq!(status_word(odd), UNKNOWN, "{odd:?}");
        }
    }
}
