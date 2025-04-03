use tabled::{Tabled, derive::display};
use crate::display::format_url;

#[derive(Tabled)]
pub struct Details {
  #[tabled(display("display::option", ""))]
  pub info: Option<String>,
  #[tabled(display("display::option", ""))]
  pub library: Option<String>,
  #[tabled(display="format_url")]
  pub documentation: Option<String>
}

#[derive(Tabled)]
pub struct SuspectImport<'a> {
  pub name: &'a String,
  #[tabled(inline)]
  pub details: Option<&'a Details>
}
