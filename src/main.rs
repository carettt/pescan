use clap::Parser;
use anyhow::{Result, anyhow, bail};
use camino::Utf8PathBuf;
use goblin::{Object, pe::import::Import};
use scraper::{Html, Selector};

use std::fs;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
  file: Utf8PathBuf
}

#[derive(Debug)]
struct FlatImport {
  name: String,
  dll: String
}

fn flatten_imports(raw_imports: &Vec<Import>) -> Vec<FlatImport> {
  return raw_imports.iter().map(|i| FlatImport { name: i.name.to_string(), dll: i.dll.to_string() }).collect();
}

fn get_headers(document: &Html) -> Result<Vec<String>> {
  let header_selector = Selector::parse("th")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?;

  let headers: Vec<String> = document.select(&header_selector)
    .map(|element| {
      let mut inner_html = element.inner_html();

      if let Some((before, _)) = inner_html.split_once(' ') {
        inner_html = before.to_string();
      }

      inner_html
    }).collect();

  Ok(headers)
}

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
  let apis = get_apis(&document);

  println!("{:#?}", headers);
  println!("{:#?}", apis);

  match Object::parse(&file_buffer)? {
    Object::PE(pe) => {
      let imports = flatten_imports(&pe.imports);
      std::mem::drop(pe);
    },
    _ => {
      bail!("invalid file type, only PE files are supported");
    }
  }

  Ok(())
}
