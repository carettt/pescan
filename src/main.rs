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
use tabled::{
  derive::display,
  settings::{location::ByColumnName, object::{Columns, Rows}, Remove, Width},
  Table,
  Tabled
};

use std::fs;
use std::collections::hash_set::HashSet;
use std::sync::Arc;

/// pescan - static analysis tool for PE files via API import analysis
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
  /// Sample File
  file: Utf8PathBuf,

  /// Show summary of API functionality
  #[arg(short, long)]
  info: bool,
  /// Show DLL library of API
  #[arg(short, long)]
  library: bool,
  /// Show link to documentation of API
  #[arg(short, long)]
  documentation: bool,
  /// Alias for -ild
  #[arg(short='A', long)]
  all: bool,

  /// Maximum width of tables
  #[arg(short, long, default_value_t=80)]
  width: usize,

  /// Maximum amount of threads used to make requests to https://malapi.io
  #[arg(short, long, default_value_t=4)]
  threads: usize
}

#[derive(Tabled)]
struct Details {
  #[tabled(display("display::option", ""))]
  info: Option<String>,
  #[tabled(display("display::option", ""))]
  library: Option<String>,
  #[tabled(display="format_url")]
  documentation: Option<String>
}

#[derive(Tabled)]
struct SuspectImport<'a> {
  name: &'a String,
  #[tabled(inline)]
  details: Option<&'a Details>
}

/// Flattens `Vec` of [Import]s into `Vec` of [String]s
fn flatten_imports(raw_imports: &[Import]) -> Vec<String> {
  return raw_imports.iter()
    .map(|i| i.name.to_string()).collect();
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

/// Scrapes info/library/documentation URL from details pages of APIs,
/// <https://malapi.io>/winapi/{NAME}.
/// Performs requests asynchronously (number of threads can be set with `-t`)
async fn get_details(imports: Vec<Vec<String>>, args: Arc<Args>) -> Result<Vec<Vec<Details>>> {
  let mut details: Vec<Vec<Details>> = Vec::with_capacity(imports.len());

  let semaphore = Arc::new(Semaphore::new(args.threads));

  let client = Arc::new(reqwest::Client::builder()
    .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
    .build()?);

  let details_url = Arc::new(String::from("https://malapi.io/winapi/"));
  let details_selector = Arc::new(Selector::parse(".content")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?);

  for category in imports.iter().cloned() {
    let mut handles: Vec<task::JoinHandle<Result<Details>>> = Vec::with_capacity(category.len());

    for import in category {
      let semaphore = Arc::clone(&semaphore);
      let client = Arc::clone(&client);

      let details_url = Arc::clone(&details_url);
      let details_selector = Arc::clone(&details_selector);

      let args = Arc::clone(&args);

      let handle: task::JoinHandle<Result<Details>> = task::spawn(async move {
        let _ = semaphore.acquire().await?;

        let mut info: Option<String> = None;
        let mut library: Option<String> = None;
        let mut documentation: Option<String> = None;

        let page = client.get(format!("{details_url}{import}"))
          .send().await?
          .text().await?;
        let document = Html::parse_document(&page);

        let content = document.select(&details_selector)
          .collect::<Vec<_>>();

        if args.info || args.all {
          info = Some(content.get(1)
            .context("could not find info")?
            .text().collect::<String>().trim().to_string());
        }

        if args.library || args.all {
          library = Some(content.get(2)
            .context("could not find library")?
            .text().collect::<String>().trim().to_string());
        }

        if args.documentation || args.all {
          documentation = Some(content.get(4)
            .context("could not find documentation")?
            .text().collect::<String>().trim().to_string());
        }

        Ok(Details { info, library, documentation })
      });

      handles.push(handle);
    }

    let mut detail: Vec<Details> = Vec::with_capacity(handles.len());

    for handle in handles {
      detail.push(handle.await??);
    }

    details.push(detail);
  }

  Ok(details)
}

fn format_url(url: &Option<String>) -> String {
  if let Some(url) = url {
    format!("\x1B]8;;{}\x1B\\{}\x1B]8;;\x1B\\", url, "[link]")
  } else {
    String::from("")
  }
}

fn create_tables(headers: &[String], data: &[Vec<SuspectImport>], total_width: &usize)
  -> Vec<(String, Table)> {
  let mut tables: Vec<(String, Table)> = Vec::with_capacity(headers.len());

  for (i, category) in data.iter().enumerate() {
    let mut total_columns = 4;
    let mut table = (headers[i].to_owned(),
      Table::new(category));

    if category.len() > 0 {
      if let Some(details) = category[0].details {
        if let None = details.info {
          table.1.with(Remove::column(ByColumnName::new("info")));
          total_columns -= 1;
        }
        if let None = details.library {
          table.1.with(Remove::column(ByColumnName::new("library")));
          total_columns -= 1;
        }
        if let None = details.documentation {
          table.1.with(Remove::column(ByColumnName::new("documentation")));
          total_columns -= 1;
        }
      } else {
        table.1.with(Remove::column(Columns::new(1..=3)));
        total_columns -= 3;
      }
    }

    table.1.modify(Rows::new(0..), Width::wrap(total_width / total_columns).keep_words(true));

    tables.push(table);
  }

  tables
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Arc::new(Args::parse());
  
  let file_buffer = fs::read(&args.file)?;
  let sample_html = fs::read_to_string(Utf8PathBuf::from("../source.html"))?;
  let table  = Html::parse_document(&sample_html);
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
              SuspectImport { name: import, details: Some(&details[i][j]) }
            );
          } else {
            suspect_imports[i].push(
              SuspectImport { name: import, details: None }
            );
          }
        }
      }

      let tables = create_tables(&headers, &suspect_imports, &args.width);

      for (i, (header, table)) in tables.iter().enumerate() {
        if suspect_imports[i].len() > 0 {
          println!("{header}:");
          println!("{table}");
        }
      }
    },
    _ => {
      bail!("invalid file type, only PE files are supported");
    }
  }


  Ok(())
}
