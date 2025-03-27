#![warn(missing_docs)]

//! PEScan is a malware analysis tool that scans portable executable (PE)
//! files for potentially malicious Windows API imports.
//! The program uses [HashSet](std::collections::hash_set::HashSet)s for
//! maximum efficiency in comparing import lists.
//! The binary can output in multiple formats and provide
//! a potential attack chain for the sample.

use clap::Parser;
use anyhow::{Result, anyhow, bail};
use camino::Utf8PathBuf;
use goblin::{Object, pe::import::Import};
use scraper::{Html, Selector};

use std::fs;
use std::collections::hash_set::HashSet;


/// pescan - static analysis tool for PE files via API import analysis
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
  file: Utf8PathBuf,

  #[arg(short, long)]
  description: bool
}


/// [FlatImport] is a utility struct to flatten the PE imports returned by the [goblin] crate
#[derive(Debug)]
struct FlatImport {
  name: String,
  dll: String
}

/// Flattens [goblin::pe::import::Import] into [FlatImport]
fn flatten_imports(raw_imports: &Vec<Import>) -> Vec<FlatImport> {
  return raw_imports.iter()
    .map(|i| FlatImport { name: i.name.to_string(), dll: i.dll.to_string() }).collect();
}

/// Scrapes headers from HTML fetched from <https://malapi.io>
fn get_headers(document: &Html) -> Result<Vec<String>> {
  let header_selector = Selector::parse("th")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?;

  let headers: Vec<String> = document.select(&header_selector)
    .map(|element| element.text().map(|s| s.trim()).collect()).collect();

  Ok(headers)
}

/// Scrapes APIs from HTML fetched from <https://malapi.io>
fn get_apis(document: &Html) -> Result<Vec<Vec<String>>> {
  let mut apis: Vec<Vec<String>> = Vec::new();
  let column_selector = Selector::parse("td > table > tbody")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?;
  let api_selector = Selector::parse(".map-item")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?;

  document.select(&column_selector)
    .for_each(|column| {
      apis.push(column.select(&api_selector)
        .map(|cell| cell.text().collect())
        .collect());
    });

  Ok(apis)
}

fn main() -> Result<()> {
  let args = Args::parse();
  
  let file_buffer = fs::read(args.file)?;
  let sample_html = fs::read_to_string(Utf8PathBuf::from("../source.html"))?;
  let document  = Html::parse_document(&sample_html);
  let headers = get_headers(&document)?;
  let apis = get_apis(&document)?;

  match Object::parse(&file_buffer)? {
    Object::PE(pe) => {
      let imports = flatten_imports(&pe.imports);
      let mut suspicious_imports = Vec::<Vec<String>>::new();

      std::mem::drop(pe);

      for category in apis.iter() {
        let category_set = category.iter().cloned().collect::<HashSet<String>>();
        let import_set = imports.iter().map(|i| i.name.clone()).collect::<HashSet<String>>();

        suspicious_imports.push(category_set.intersection(&import_set).cloned().collect());
      }

      for (i, header) in headers.iter().enumerate() {
        if !suspicious_imports[i].is_empty() {
          println!("{header}: [");
          for import in &suspicious_imports[i] {
            println!("\t{import},");
          }
          println!("]");
        }
      }

    },
    _ => {
      bail!("invalid file type, only PE files are supported");
    }
  }

  Ok(())
}
