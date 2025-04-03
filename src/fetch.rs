//! Provides functions used to scrape API data from
//! <https://malapi.io>.

use anyhow::{Result, Context, anyhow};
use scraper::{Html, Selector};
use tokio::sync::Semaphore;
use tokio::task;

use std::sync::Arc;

use crate::args::Args;
use crate::output::Details;

/// Scrapes headers from HTML fetched from <https://malapi.io>
pub fn get_headers(document: &Html) -> Result<Vec<String>> {
  let client = reqwest::Client::builder()
      .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
      .build()?;
  let header_selector = Selector::parse("th")
    .map_err(|e| anyhow!("failed to parse selector: {e}"))?;

  let headers: Vec<String> = document.select(&header_selector)
    .map(|element| element.text().map(|s| s.trim()).collect()).collect();

  Ok(headers)
}

/// Scrapes APIs from HTML fetched from <https://malapi.io>
pub fn get_apis(document: &Html) -> Result<Vec<Vec<String>>> {
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
pub async fn get_details(imports: Vec<Vec<String>>, args: Arc<Args>) -> Result<Vec<Vec<Details>>> {
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
