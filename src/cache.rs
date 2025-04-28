//! Provides [Cache] struct for loading and creating a cache of APIs

use serde::{Serialize, Deserialize};
use anyhow::{Result, Context, anyhow};
use scraper::{Selector, Html};
use indicatif::{ProgressBar, ProgressStyle};

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::fs::{self, File};
use std::time::Duration;

/// Wrapper for API data for caching purposes
#[derive(Default, Clone)]
#[derive(Serialize, Deserialize)]
pub struct Api {
  name: String,

  /// Summary of API functionality
  pub info: String,
  /// DLL which API originated
  pub library: String,
  /// Link to documentation web page
  pub documentation: String,
}

impl PartialEq for Api {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
  }
}

impl Eq for Api {}

impl Hash for Api {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.name.hash(state);
  }
}

/// Wrapper around APIs and headers for caching purposes
#[derive(Default)]
#[derive(Serialize, Deserialize)]
pub struct Cache {
  headers: Vec<String>,
  apis: Vec<HashSet<Api>>
}

impl Cache {
  /// Scrape headers from index page
  fn scrape_headers(&mut self, document: &Html) -> Result<()> {
    let header_selector = Selector::parse("th")
      .map_err(|e| anyhow!("failed to parse selector: {e}"))?;

    self.headers = document.select(&header_selector)
      .map(|element| element.text().map(|s| s.trim()).collect()).collect();

    Ok(())
  }

  /// Scrape API list from index page (for individual detail fetching)
  fn scrape_apis(document: &Html) -> Result<Vec<Vec<String>>> {
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

  /// Fetch details for all apis from <https://malapi.io> for caching
  pub async fn update(
    &mut self
  ) -> Result<()> {
    let client = reqwest::Client::builder()
      .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
      .cookie_store(false)
      .build()?;

    let details_url = String::from("https://malapi.io/winapi/");
    let details_selector = Selector::parse(".content")
      .map_err(|e| anyhow!("failed to parse selector: {e}"))?;

    let index = Html::parse_document(
      &client.get("https://malapi.io")
        .send().await?
        .text().await?
    );

    let apis = Self::scrape_apis(&index)?;
    self.scrape_headers(&index)?;

    self.apis = Vec::with_capacity(apis.len());

    for (i, category) in apis.iter().enumerate() {
      let bar = ProgressBar::new(category.len().try_into()?);
      bar.set_style(
        ProgressStyle::with_template("{prefix}: {msg}\n{spinner} {elapsed_precise} [{bar:40}] {pos}/{len}")?
        .progress_chars("=>-")
      );
      bar.enable_steady_tick(Duration::from_millis(100));
      bar.set_prefix(self.headers[i].clone());

      self.apis.push(HashSet::with_capacity(category.len()));

      for api in category {
        bar.set_message(api.clone());

        let res = client.get(format!("{details_url}{api}")).send().await?;

        if res.status() == reqwest::StatusCode::NOT_ACCEPTABLE {
          bar.set_message(format!("{api} unreachable!"));
          eprintln!();
          continue;
        }

        let page = res.text().await?;
        let document = Html::parse_document(&page);

        let content = document.select(&details_selector)
          .collect::<Vec<_>>();

        let info = content.get(1)
          .context("could not find info")?
          .text().collect::<String>().trim().to_string();

        let library = content.get(2)
          .context("could not find library")?
          .text().collect::<String>().trim().to_string();

        let documentation = content.get(4)
          .context("could not find documentation")?
          .text().collect::<String>().trim().to_string();

        self.apis[i].insert(Api {
          name: api.to_owned(),
          info,
          library,
          documentation
        });

        bar.inc(1);
      }
      bar.set_message("done!");
      bar.finish();
    }

    Ok(())
  }
  
  /// Load cache from `apis.mpk` file if it exists, update and create if not.
  /// If no valid home directory is found, it still updates the `Cache` struct
  /// but does not save for future execution
  pub async fn load(update: bool) -> Result<Cache> {
    let mut cache = Cache::default();

    if let Some(cache_dir) = dirs::cache_dir() {
      let cache_file = cache_dir.join(format!("{}/data.mpk", env!("CARGO_PKG_NAME")));

      if cache_file.exists() && !update {
        let input_stream = fs::File::open(&cache_file)?;

        cache = rmp_serde::from_read(&input_stream)?;
      } else {
        if update {
          fs::remove_file(&cache_file)?;
        }

        let cache_dir = cache_file.parent().context("invalid cache directory path")?;
        let mut output_stream: File;

        cache.update().await?;

        fs::create_dir_all(cache_dir)?;
        output_stream = fs::File::create_new(&cache_file)?;
        rmp_serde::encode::write(&mut output_stream, &cache)?;
      }
    } else {
      eprintln!("Could not find a valid home directory for user! Data will not be cached!");
      cache.update().await?;
    }

    Ok(cache)
  }

  /// Get [Api] based on category and name for detail lookup
  pub fn get_api(&self, category_index: usize, name: &str) -> Option<&Api> {
    let lookup = Api {
      name: name.to_owned(),
      ..Default::default()
    };

    self.apis[category_index].get(&lookup)
  }

  /// Get API list from cache
  pub fn get_apis(&self) -> Vec<HashSet<String>> {
    self.apis.iter().map(|category| {
      category.iter().map(|api| {
        api.name.clone()
      }).collect()
    }).collect()
  }

  /// Get header list from cache
  pub fn get_headers(&self) -> Vec<String> {
    self.headers.clone()
  }
}
