//! Provides functions used for outputting to `stdout`.

use tabled::{
  settings::{location::ByColumnName, object::{Columns, Rows}, Remove, Width},
  Table,
};

use crate::output::Output;

/// Shortens URLs to `[link]` with OSC8 ANSI styled hyperlinks
pub fn format_url(url: &Option<String>) -> String {
  if let Some(url) = url {
    format!("\x1B]8;;{}\x1B\\{}\x1B]8;;\x1B\\", url, "[link]")
  } else {
    String::from("")
  }
}

/// Creates a [Vec] of pairs of headers and tables constrained
/// to a certain width (approximately).
pub fn create_tables(output: &Output, total_width: &usize)
  -> Vec<(String, Table)> {
  let mut tables: Vec<(String, Table)> = Vec::with_capacity(output.headers.len());

  for (i, category) in output.suspect_imports.iter().enumerate() {
    let mut total_columns = 4;
    let mut table = (output.headers[i].to_owned(),
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
