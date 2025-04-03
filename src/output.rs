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
  /// Comma Separated Values
  CSV,
}

#[skip_serializing_none]
#[derive(Serialize, Tabled)]
pub struct Details {
  #[tabled(display("display::option", ""))]
  pub info: Option<String>,
  #[tabled(display("display::option", ""))]
  pub library: Option<String>,
  #[tabled(display="format_url")]
  pub documentation: Option<String>
}

#[skip_serializing_none]
#[derive(Serialize, Tabled)]
pub struct SuspectImport<'a> {
  pub name: &'a String,
  #[tabled(inline)]
  pub details: Option<&'a Details>
}

pub struct Output<'b> {
  pub headers: Vec<String>,
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
      if category.len() > 0 {
        map.serialize_entry(header, category)?;
      }
    }

    map.end()
  }
}

impl Output<'_> {
  pub fn display(&self, width: &usize) {
    let tables = create_tables(self, width);

    for (i, (header, table)) in tables.iter().enumerate() {
      if self.suspect_imports[i].len() > 0 {
        println!("{header}:");
        println!("{table}");
      }
    }
  }

  pub fn txt(&self, path: &Utf8PathBuf, width: &usize) -> Result<()> {
    let mut file = File::create_new(path)?;
    let tables = create_tables(self, width);

    for ((header, table), category) in tables.iter().zip(self.suspect_imports.iter()) {
      if category.len() > 0 {
        writeln!(file, "{header}:").context("could not write header to file")?;
        writeln!(file, "{table}").context("could not write table to file")?;
      }
    }

    Ok(())
  }

  pub fn json(&self, path: &Utf8PathBuf) -> Result<()> {
    let mut file = File::create_new(path)?;
    let json = serde_json::to_string_pretty(self)?;

    writeln!(file, "{json}")?;

    Ok(())
  }

  pub fn yaml(&self, path: &Utf8PathBuf) -> Result<()> {
    let mut file = File::create_new(path)?;
    let yaml = serde_yml::to_string(self)?;

    writeln!(file, "{yaml}")?;

    Ok(())
  }

  pub fn toml(&self, path: &Utf8PathBuf) -> Result<()> {
    let mut file = File::create_new(path)?;
    let toml = toml::to_string_pretty(self)?;

    writeln!(file, "{toml}")?;

    Ok(())
  }

  pub fn csv(&self, path: &Utf8PathBuf) -> Result<()> {
    if path.is_dir() {
      for (header, category) in self.headers.iter().zip(self.suspect_imports.iter()) {
        if category.len() > 0 {
          let file = File::create_new(path.join(format!("{header}.csv")))?;
          let mut wtr = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);

          let mut table_headers = vec![String::from("name")];
          if let Some(details) = category[0].details {
            if details.info.is_some() {
              table_headers.push(String::from("info"));
            }
            if details.library.is_some() {
              table_headers.push(String::from("library"));
            }
            if details.documentation.is_some() {
              table_headers.push(String::from("documentation"));
            }
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
}
