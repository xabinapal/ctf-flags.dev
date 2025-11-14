module Jekyll
  module StripBlockHtmlFilter
    def strip_block_html(input)
      return '' if input.nil? || input.to_s.strip.empty?

      text = input.to_s
      
      # Common block-level HTML elements
      # This list includes standard HTML5 block elements
      block_elements = %w[
        address article aside blockquote body dd details dialog div dl dt
        fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header
        hgroup hr li main nav ol p pre section summary table tbody td
        tfoot th thead tr ul
      ]
      
      # Build regex pattern to match opening and closing tags for block elements
      # Pattern matches: <tag>, <tag attr="...">, </tag>, and self-closing tags
      block_elements.each do |tag|
        # Remove opening tags: <tag> or <tag attributes>
        text = text.gsub(/<#{tag}(?:\s[^>]*)?>/i, '')
        # Remove closing tags: </tag>
        text = text.gsub(/<\/#{tag}>/i, '')
      end
      
      text
    end
  end
end

Liquid::Template.register_filter(Jekyll::StripBlockHtmlFilter)

