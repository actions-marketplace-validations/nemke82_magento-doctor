//! mdoctor_magento: Discovery, configuration parsing, and XML modeling for Magento 2.

pub mod collector;
pub mod composer_parser;
pub mod discovery;
pub mod env_parser;
pub mod module_parser;
pub mod xml;

pub use collector::collect_installation;
pub use discovery::{discover_magento_root, is_valid_magento_root};
pub use env_parser::parse_env_php;
pub use module_parser::{classify_module, discover_modules, parse_config_php};
pub use xml::layout::{parse_layout_xml, parse_layout_xml_str};
