#![warn(missing_docs)]

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

use crate::args::Args;
use crate::output::{Details, SuspectImport};
use crate::fetch::{get_headers, get_apis, get_details};

/// Flattens `Vec` of [Import]s into `Vec` of [String]s
fn flatten_imports(raw_imports: &[Import]) -> Vec<String> {
  return raw_imports.iter()
    .map(|i| i.name.to_string()).collect();
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Arc::new(Args::parse());

  let client = reqwest::Client::builder()
    .user_agent(format!("{}/{}",
        env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
    .build()?;
  
  let file_buffer = fs::read(&args.sample)?;
  let table  = Html::parse_document(
    &client.get("https://malapi.io")
      .send().await?
      .text().await?
  );
  let headers = get_headers(&table)?;
  let apis = get_apis(&table)?;

  match Object::parse(&file_buffer)? {
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
            suspicious_imports.iter().cloned().collect(),
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
                info: &details[i][j].info,
                library: &details[i][j].library,
                documentation: &details[i][j].documentation
              }
            );
          } else {
            suspect_imports[i].push(
              SuspectImport {
                name: import,
                info: &None,
                library: &None,
                documentation: &None
              }
            );
          }
        }
      }

      let output = Output { headers, suspect_imports };

      if let Some(file) = &args.path {
        match &args.format {
          Format::TXT => output.txt(file, &args.width)?,
          Format::JSON => output.json(file)?,
          Format::YAML => output.yaml(file)?,
          Format::TOML => output.toml(file)?,
          Format::CSV => output.csv(file)?
        }
      } else {
        output.display(&args.width);
      }
    },
    _ => {
      bail!("invalid file type, only PE files are supported");
    }
  }


  Ok(())
}
