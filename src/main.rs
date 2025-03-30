#![warn(missing_docs)]

//! PEScan is a malware analysis tool that scans portable executable (PE)
//! files for potentially malicious Windows API imports.
//! The program uses [HashSet]s for
//! maximum efficiency in comparing import lists.
//! The binary can output in multiple formats and provide
//! a potential attack chain for the sample.

use clap::Parser;
use anyhow::{Result, Context, anyhow, bail};
use camino::Utf8PathBuf;
use goblin::{Object, pe::import::Import};
use scraper::{Html, Selector};
use tokio::sync::Semaphore;
use tokio::task;

use std::fs;
use std::collections::hash_set::HashSet;
use std::sync::Arc;

/// pescan - static analysis tool for PE files via API import analysis
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
  file: Utf8PathBuf,

  #[arg(short, long)]
  description: bool,
  #[arg(short, long, default_value_t=4)]
  threads: usize
}


/// [FlatImport] is a utility struct to flatten the PE imports returned by the [goblin] crate
#[derive(Debug)]
struct FlatImport {
  name: String,
  dll: String
}

struct Output {
}

/// Flattens [Import] into [FlatImport]
fn flatten_imports(raw_imports: &[Import]) -> Vec<FlatImport> {
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

/// Scrapes descriptions from details pages of APIs, <https://malapi.io>/winapi/{NAME}.
/// Performs requests asynchronously (number of threads can be set with `-t`)
async fn get_details(imports: Vec<Vec<String>>, max_threads: &usize) -> Result<Vec<Vec<String>>> {
  let mut details: Vec<Vec<String>> = Vec::with_capacity(imports.len());

  let semaphore = Arc::new(Semaphore::new(*max_threads));

  let client = Arc::new(reqwest::Client::builder()
    .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
    .build()?);

  let details_url = Arc::new(String::from("https://malapi.io/winapi/"));
  let details_selector = Arc::new(Selector::parse(".content")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?);

  for category in imports {
    let mut handles: Vec<task::JoinHandle<Result<String>>> = Vec::with_capacity(category.len());

    for import in category {
      let semaphore = Arc::clone(&semaphore);
      let client = Arc::clone(&client);

      let details_url = Arc::clone(&details_url);
      let details_selector = Arc::clone(&details_selector);
      
      let handle: task::JoinHandle<Result<String>> = task::spawn(async move {
        let _ = semaphore.acquire().await?;

        let page = client.get(format!("{details_url}{import}"))
          .send().await?
          .text().await?;
        let details = Html::parse_document(&page);

        let description = details.select(&details_selector)
          .nth(1).context("cannot find description")?
          .text().collect::<String>();

        Ok(description.trim().into())
      });

      handles.push(handle);
    }

    let mut descriptions: Vec<String> = Vec::with_capacity(handles.len());

    for handle in handles {
      descriptions.push(handle.await??);
    }

    details.push(descriptions);
  }

  Ok(details)
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Args::parse();
  
  let file_buffer = fs::read(args.file)?;
  let sample_html = fs::read_to_string(Utf8PathBuf::from("../source.html"))?;
  let table  = Html::parse_document(&sample_html);
  let headers = get_headers(&table)?;
  let apis = get_apis(&table)?;

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

      let details = get_details(suspicious_imports.clone(), &args.threads).await?;

      for (i, header) in headers.iter().enumerate() {
        if !suspicious_imports[i].is_empty() {
          println!("{header}: [");
          for (j, import) in suspicious_imports[i].iter().enumerate() {
            print!("\t{import}");

            if args.description {
              println!(": {{");
              println!("\t\t{}", details[i][j]);
              println!("\t}},");
            } else {
              println!(",");
            }
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
