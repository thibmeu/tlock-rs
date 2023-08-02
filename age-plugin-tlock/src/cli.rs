use clap::Parser;

/// Plugin for age to interact with tlock encryption
///
/// INPUT defaults to standard input, and OUTPUT defaults to standard output.
///
/// ROUND can be:
/// * a specific round (123),
/// * a duration (30s),
/// * an RFC3339 date (2023-06-28 21:30:22)
///
/// REMOTE is a drand remote URL. You can find a non-exhaustive list on https://github.com/thibmeu/drand-rs#common-remotes.
///
/// Example:
///     $ age-plugin-tlock --generate --remote <URL> > fastnet.key
///     $ cat fastnet.key | grep 'recipient' | sed 's/.*\(age1.*\)/\1/' > fastnet.key.pub
///     $ tar cvz ~/data | ROUND="<ROUND>" age -R myremote.key.pub > data.tar.gz.age
///     $ age --decrypt -o data.tar.gz data.tar.gz.age
#[derive(Parser)]
#[command(author, version, about, verbatim_doc_comment)]
#[command(propagate_version = true)]
pub struct Cli {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,
    #[arg(long, hide = true)]
    pub age_plugin: Option<String>,
    #[arg(long, default_value_t = false)]
    pub generate: bool,
    /// REMOTE is a drand remote URL. You can find a non-exhaustive list on https://github.com/thibmeu/drand-rs#common-remotes.
    #[arg(short, long)]
    pub remote: Option<String>,
}

#[allow(dead_code)]
pub fn build() -> Cli {
    Cli::parse()
}
