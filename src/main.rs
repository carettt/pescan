#![warn(missing_docs)]
#![allow(clippy::all)]

//! PEScan is a malware analysis tool that scans portable executable (PE)
//! files for potentially malicious Windows API imports.
//! The program uses [HashSet]s for
//! maximum efficiency in comparing import lists.
//! The binary can output in multiple formats and provide
//! a potential attack chain for the sample.

pub mod args;
pub mod display;
pub mod output;
pub mod fetch;

use clap::Parser;
use anyhow::{Result, bail};
use goblin::{Object, pe::import::Import};
use output::{Format, Output};
use scraper::Html;

use std::fs;
use std::collections::hash_set::HashSet;
use std::sync::Arc;
use std::io::{Read, Write, IsTerminal};

use crate::args::Args;
use crate::output::{Details, SuspectImport};
use crate::fetch::{get_headers, get_apis, get_details};

/// Flattens `Vec` of [Import]s into `Vec` of [String]s
fn flatten_imports(raw_imports: &[Import]) -> Vec<String> {
  raw_imports.iter()
    .map(|i| i.name.to_string()).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Arc::new(Args::parse());

  let client = reqwest::Client::builder()
    .user_agent(format!("{}/{}",
        env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
    .build()?;
  
  let table  = Html::parse_document(
    &client.get("https://malapi.io")
      .send().await?
      .text().await?
  );
  let headers = get_headers(&table)?;
  let apis = get_apis(&table)?;

  let mut sample_buffer: Vec<u8> = Vec::new();

  if let Some(path) = &args.path {
    sample_buffer = fs::read(path)?;
  } else {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
      let _ = std::io::stdin().read_to_end(&mut sample_buffer)?;
    } else {
      bail!("sample not found in [FILE] or stdin.");
    }
  }

  match Object::parse(&sample_buffer)? {
    Object::PE(pe) => {
      let imports = flatten_imports(&pe.imports);
      let mut suspicious_imports = Vec::new();
      let mut details: Option<Vec<Vec<Details>>> = None;

      std::mem::drop(pe);

      for category in apis.iter() {
        let category_set = category.iter().cloned().collect::<HashSet<String>>();
        let import_set = imports.iter().cloned().collect::<HashSet<String>>();

        suspicious_imports.push(category_set.intersection(&import_set).cloned().collect());
      }

      if args.info || args.library || args.documentation || args.all {
        details = Some(
          get_details(
            suspicious_imports.to_vec(),
            Arc::clone(&args)
          ).await?
        );
      }

      let mut suspect_imports: Vec<Vec<SuspectImport>> = Vec::with_capacity(suspicious_imports.len());

      for i in 0..suspicious_imports.len() {
        suspect_imports.push(Vec::new());
        for (j, import) in suspicious_imports[i].iter().enumerate() {
          if let Some(details) = &details {
            suspect_imports[i].push(
              SuspectImport {
                name: import,
                info: details[i][j].info.as_ref(),
                library: details[i][j].library.as_ref(),
                documentation: details[i][j].documentation.as_ref()
              }
            );
          } else {
            suspect_imports[i].push(
              SuspectImport {
                name: import,
                info: None,
                library: None,
                documentation: None
              }
            );
          }
        }
      }

      let output = Output { headers, suspect_imports };

      match &args.format {
        Format::CSV => {
          if let Some(path) = &args.path {
            output.csv_to_file(path)?;
          } else {
            output.csv_to_stdout()?;
          }
        },
        _ => {
          let mut buf: Box<dyn Write> = if let Some(path) = &args.path {
            Box::new(fs::File::create_new(path)?)
          } else {
            Box::new(std::io::stdout())
          };

          match &args.format {
            Format::TXT => output.txt(&mut buf, &args.width)?,
            Format::JSON => output.json(&mut buf)?,
            Format::YAML => output.yaml(&mut buf)?,
            Format::TOML => output.toml(&mut buf)?,
            Format::CSV => unreachable!()
          }
        }
      }
    },
    _ => {
      bail!("invalid file type, only PE files are supported");
    }
  }


  Ok(())
}
