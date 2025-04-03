use clap::Parser;
use camino::Utf8PathBuf;

/// pescan - static analysis tool for PE files via API import analysis
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
  /// Sample File
  pub file: Utf8PathBuf,

  /// Show summary of API functionality
  #[arg(short, long)]
  pub info: bool,
  /// Show DLL library of API
  #[arg(short, long)]
  pub library: bool,
  /// Show link to documentation of API
  #[arg(short, long)]
  pub documentation: bool,
  /// Alias for -ild
  #[arg(short='A', long)]
  pub all: bool,

  /// Maximum width of tables
  #[arg(short, long, default_value_t=80)]
  pub width: usize,

  /// Maximum amount of threads used to make requests to https://malapi.io
  #[arg(short, long, default_value_t=4)]
  pub threads: usize
}
