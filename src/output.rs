//! Provides [Format] enum containing supported output formats,
//! and structs for abstracting import data to output.

use serde_with::skip_serializing_none;
use tabled::{Tabled, derive::display};
use serde::{ser::SerializeMap, Serialize, Serializer};
use clap::ValueEnum;
use camino::Utf8PathBuf;
use anyhow::{Context, Result, anyhow};

use std::fs::File;
use std::io::Write;

use crate::display::{create_tables, format_url};

/// All possible output formats (set with -f or --format)
#[non_exhaustive]
#[derive(Clone, ValueEnum)]
pub enum Format {
  /// Standard output
  TXT,
  /// JavaScript Object Notation
  JSON,
  /// Yet Another Markup Language
  YAML,
  /// Tom's Obvious Minimal Language
  TOML,
  /// Comma Separated Values, WARNING: output path MUST be directory
  CSV,
}

/// Contains optional details about imports. Set using `-i`, -`l`, and
/// `-d` flags .
pub struct Details {
  /// Summary of API functionality
  pub info: Option<String>,
  /// Library from which API is imported
  pub library: Option<String>,
  /// Link to API documentation
  pub documentation: Option<String>
}

/// Contains all of the suspect API's relevant data
#[skip_serializing_none]
#[derive(Serialize, Tabled)]
pub struct SuspectImport<'a> {
  /// Name of API
  pub name: &'a String,
  /// Summary of API functionality
  #[tabled(display("display::option", ""))]
  pub info: Option<&'a String>,
  /// Library from which API is imported
  #[tabled(display("display::option", ""))]
  pub library: Option<&'a String>,
  /// Link to API documentation
  #[tabled(display("format_url"))]
  pub documentation: Option<&'a String>,
}

/// Wrapper to group headers and suspect imports for outputting
pub struct Output<'b> {
  /// [Vec] of technique categories
  pub headers: Vec<String>,
  /// 2D [Vec] of suspect APIs by technique category
  pub suspect_imports: Vec<Vec<SuspectImport<'b>>>
}

impl Serialize for Output<'_> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer
  {
    if self.headers.len() != self.suspect_imports.len() {
      return Err(serde::ser::Error::custom(
          "headers and suspect_imports are different lengths"
      ));
    }

    let mut map = serializer.serialize_map(Some(self.headers.len()))?;

    for (header, category) in self.headers.iter().zip(self.suspect_imports.iter()) {
      if !category.is_empty() {
        map.serialize_entry(header, category)?;
      }
    }

    map.end()
  }
}

impl Output<'_> {
  /// Output to `buf` as plain text
  pub fn txt<T: Write>(&self, buf: &mut T, width: &usize) -> Result<()> {
    let tables = create_tables(self, width);

    for ((header, table), category) in tables.iter().zip(self.suspect_imports.iter()) {
      if !category.is_empty() {
        writeln!(buf, "{header}:").context("could not write header to file")?;
        writeln!(buf, "{table}").context("could not write table to file")?;
      }
    }

    Ok(())
  }

  /// Output to `buf` as JSON
  pub fn json<T: Write>(&self, buf: &mut T) -> Result<()> {
    let json = serde_json::to_string_pretty(self)?;

    writeln!(buf, "{json}")?;

    Ok(())
  }

  /// Output to `buf` as YAML
  pub fn yaml<T: Write>(&self, buf: &mut T) -> Result<()> {
    let yaml = serde_yml::to_string(self)?;

    writeln!(buf, "{yaml}")?;

    Ok(())
  }

  /// Output to `buf` as TOML
  pub fn toml<T: Write>(&self, buf: &mut T) -> Result<()> {
    let toml = toml::to_string_pretty(self)?;

    writeln!(buf, "{toml}")?;

    Ok(())
  }

  /// Output to `path/{HEADER}.csv` as CSV
  pub fn csv_to_file(&self, path: &Utf8PathBuf) -> Result<()> {
    if path.is_dir() {
      for (header, category) in self.headers.iter().zip(self.suspect_imports.iter()) {
        if !category.is_empty() {
          let file = File::create_new(path.join(format!("{header}.csv")))?;
          let mut wtr = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);

          let mut table_headers = vec![String::from("name")];
          if category[0].info.is_some() {
            table_headers.push(String::from("info"));
          }
          if category[0].library.is_some() {
            table_headers.push(String::from("library"));
          }
          if category[0].documentation.is_some() {
            table_headers.push(String::from("documentation"));
          }

          wtr.write_record(&table_headers)?;

          for import in category {
            wtr.serialize(import)?;
          }

          wtr.flush()?;
        }
      }

      Ok(())
    } else {
      Err(anyhow!("csv format requires output path to be directory"))
    }
  }

  /// Output to stdout as CSV
  pub fn csv_to_stdout(&self) -> Result<()> {
    for (header, category) in self.headers.iter().zip(self.suspect_imports.iter()) {
      if !category.is_empty() {
        let mut wtr = csv::WriterBuilder::new()
          .has_headers(false)
          .from_writer(std::io::stdout());

        println!("{header}:");
        std::io::stdout().flush()?;

        let mut table_headers = vec![String::from("name")];
        if category[0].info.is_some() {
          table_headers.push(String::from("info"));
        }
        if category[0].library.is_some() {
          table_headers.push(String::from("library"));
        }
        if category[0].documentation.is_some() {
          table_headers.push(String::from("documentation"));
        }

        wtr.write_record(&table_headers)?;

        for import in category {
          wtr.serialize(import)?;
        }

        wtr.flush()?;
        println!();
      }
    }

    Ok(())
  }
}
