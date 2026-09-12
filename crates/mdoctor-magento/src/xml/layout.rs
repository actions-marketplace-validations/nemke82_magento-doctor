//! Layout XML parser detecting uncacheable blocks (cacheable="false").

use std::path::Path;
use mdoctor_core::UncacheableBlock;

/// Parse a layout XML file and return any blocks declaring cacheable="false".
pub fn parse_layout_xml(file_path: &Path, module_name: &str) -> Vec<UncacheableBlock> {
    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_layout_xml_str(&content, file_path, module_name)
}

/// Parse layout XML content directly.
pub fn parse_layout_xml_str(content: &str, file_path: &Path, module_name: &str) -> Vec<UncacheableBlock> {
    let mut uncacheable_blocks = Vec::new();

    let doc = match roxmltree::Document::parse(content) {
        Ok(d) => d,
        Err(_) => return uncacheable_blocks,
    };

    let layout_handle = file_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    for node in doc.descendants().filter(|n| n.has_tag_name("block")) {
        if let Some(cacheable) = node.attribute("cacheable") {
            if cacheable.trim().eq_ignore_ascii_case("false") {
                let block_name = node
                    .attribute("name")
                    .unwrap_or("unnamed_block")
                    .to_string();
                let class_name = node.attribute("class").map(|c| c.to_string());
                let template = node.attribute("template").map(|t| t.to_string());
                let line = doc.text_pos_at(node.range().start).row as usize;

                uncacheable_blocks.push(UncacheableBlock {
                    module: module_name.to_string(),
                    layout_handle: layout_handle.clone(),
                    block_name,
                    class_name,
                    template,
                    source_file: file_path.to_path_buf(),
                    line,
                });
            }
        }
    }

    uncacheable_blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uncacheable_block_in_layout() {
        let xml = r#"<?xml version="1.0"?>
<page xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:magento:framework:View/Layout/etc/page_configuration.xsd">
    <body>
        <referenceContainer name="content">
            <block class="Vendor\SocialShare\Block\Buttons" name="social.share.buttons" template="buttons.phtml" cacheable="false" />
        </referenceContainer>
    </body>
</page>"#;

        let path = Path::new("view/frontend/layout/catalog_product_view.xml");
        let blocks = parse_layout_xml_str(xml, path, "Vendor_SocialShare");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_name, "social.share.buttons");
        assert_eq!(blocks[0].class_name.as_deref(), Some("Vendor\\SocialShare\\Block\\Buttons"));
        assert_eq!(blocks[0].layout_handle, "catalog_product_view");
        assert_eq!(blocks[0].module, "Vendor_SocialShare");
    }
}
