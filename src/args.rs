//! Provides [Args] struct with [clap] derive syntax for defining
//! CLI interface

use clap::Parser;
use camino::Utf8PathBuf;

use crate::output::Format;

/// pescan - static analysis tool for PE files via API import analysis
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
  /// Sample File
  #[arg(value_name="FILE")]
  pub sample: Utf8PathBuf,

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

  /// Maximum amount of threads used to make requests to <https://malapi.io>
  #[arg(short, long, default_value_t=4)]
  pub threads: usize,

  /// Maximum width of tables
  #[arg(short, long, default_value_t=80)]
  pub width: usize,

  /// Output format
  #[arg(short, long, value_enum, default_value_t=Format::TXT)]
  pub format: Format,
  /// Output path
  #[arg(short='o', long="output", value_name="PATH")]
  pub path: Option<Utf8PathBuf>,
}
