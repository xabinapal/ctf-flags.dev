module Jekyll
  module ExtractParagraphsFilter
    def extract_paragraphs(input, num_paragraphs = 1, after_tag = '')
      return '' if input.nil? || input.to_s.strip.empty?

      html = input.to_s
      num_paragraphs = num_paragraphs.to_i
      num_paragraphs = 1 if num_paragraphs < 1
      
      # If after_tag is specified, find content after that tag
      if after_tag && !after_tag.to_s.strip.empty?
        tag_name = after_tag.to_s.strip
        # Remove < and > if present (handle both "h2" and "<h2>" formats)
        tag_name = tag_name.gsub(/^<|>$/, '')
        
        # Find the closing tag (e.g., </h2> for h2)
        closing_tag = "</#{tag_name}>"
        tag_end_index = html.index(closing_tag)
        return '' unless tag_end_index
        
        # Get content after the specified tag
        html = html[(tag_end_index + closing_tag.length)..-1] || ''
      end
      
      paragraphs = []
      remaining_html = html
      
      # Extract the requested number of paragraphs
      num_paragraphs.times do
        # Find the next <p> tag
        p_start_index = remaining_html.index('<p>')
        break unless p_start_index
        
        # Get content after the <p> tag
        content_after_p = remaining_html[(p_start_index + 3)..-1] || ''
        
        # Find the closing </p> tag
        p_end_index = content_after_p.index('</p>')
        break unless p_end_index
        
        # Extract the paragraph content
        paragraph_content = content_after_p[0...p_end_index].strip
        paragraphs << paragraph_content unless paragraph_content.empty?
        
        # Move past this paragraph for the next iteration
        remaining_html = content_after_p[(p_end_index + 4)..-1] || ''
      end
      
      paragraphs.join(' ')
    end
  end
end

Liquid::Template.register_filter(Jekyll::ExtractParagraphsFilter)

