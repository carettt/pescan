#![warn(missing_docs)]
#![allow(clippy::all)]

//! PEScan is a malware analysis tool that scans portable executable (PE)
//! files for potentially malicious Windows API imports.
//! The program uses [HashSet]s for
//! maximum efficiency in comparing import lists.
//! The binary can output in multiple formats and provide
//! a potential attack chain for the sample.

pub mod args;
pub mod output;
pub mod cache;

use clap::Parser;
use anyhow::{Result, Context, bail};
use goblin::{Object, pe::import::Import};

use std::{env, fs};
use std::collections::hash_set::HashSet;
use std::sync::Arc;
use std::io::{Read, Write, IsTerminal};

use crate::args::Args;
use crate::output::{Details, SuspectImport, Format, Output};
use crate::cache::Cache;

/// Flattens `Vec` of [Import]s into `Vec` of [String]s
fn flatten_imports(raw_imports: &[Import]) -> HashSet<String> {
  raw_imports.iter()
    .map(|i| i.name.to_string()).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Arc::new(Args::parse());

  let cache = Cache::load(args.update).await?;
  let apis = cache.get_apis();

  let mut sample_buffer: Vec<u8> = Vec::new();

  if let Some(path) = &args.sample {
    sample_buffer = fs::read(path)?;
  } else {
    let mut stdin = std::io::stdin();
    if !stdin.is_terminal() {
      let _ = stdin.read_to_end(&mut sample_buffer)?;
    } else {
      bail!("sample not found in [FILE] or stdin.");
    }
  }

  match Object::parse(&sample_buffer)
    .context(if env::var("PESCAN_DOCKER") == Ok(String::from("true")) {
      "docker container not running in interactive mode"
    } else {
      "could not parse sample"
    })?
  {
    Object::PE(pe) => {
      let imports = flatten_imports(&pe.imports);

      let mut suspicious_imports = Vec::<Vec<String>>::new();
      let mut details: Option<Vec<Vec<Details>>> = None;

      std::mem::drop(pe);

      for category in apis.iter() {
        suspicious_imports.push(category.intersection(&imports).cloned().collect());
      }

      if [args.info, args.library, args.documentation, args.all].contains(&true) {
        let mut matched_details = Vec::<Vec<Details>>::new();
        for (i, category) in suspicious_imports.iter().enumerate() {
          matched_details.push(Vec::new());
          for import in category {
            if let Some(api) = cache.get_api(i, import) {
              let mut info = None;
              let mut library = None;
              let mut documentation = None;

              if args.info || args.all {
                info = Some(api.info.clone());
              }
              if args.library || args.all {
                library = Some(api.library.clone());
              }
              if args.documentation || args.all {
                documentation = Some(api.documentation.clone());
              }

              matched_details[i].push(Details { info, library, documentation });
            } else {
              matched_details[i].push(Details::default());
            }
          }
        }

        details = Some(matched_details);
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

      let output = Output { headers: cache.headers, suspect_imports };

      match &args.format {
        Format::CSV => {
          if let Some(path) = &args.path {
            output.csv_to_file(path, &args)?;
          } else {
            output.csv_to_stdout(&args)?;
          }
        },
        _ => {
          let mut buf: Box<dyn Write> = if let Some(path) = &args.path {
            Box::new(fs::File::create_new(path)?)
          } else {
            Box::new(std::io::stdout())
          };

          match &args.format {
            Format::TXT => output.txt(&mut buf, &args)?,
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

  eprintln!("Data provided by mrd0x & contributors via https://malapi.io.");

  Ok(())
}
