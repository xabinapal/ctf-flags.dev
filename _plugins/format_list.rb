module Jekyll
  module FormatListFilter
    def format_list(input, separator = '|', item_pre = '<span>', item_post = '</span>', sep_pre = nil, sep_post = nil)
      return '' if input.nil?
      
      # Convert input to array if it's not already
      items = input.is_a?(Array) ? input : [input]
      
      # Filter out nil, empty, or blank items
      items = items.reject { |item| item.nil? || item.to_s.strip.empty? }
      
      return '' if items.empty?
      
      # Convert all arguments to strings
      separator = separator.to_s
      item_pre = item_pre.to_s
      item_post = item_post.to_s
      
      # Handle separator wrapper - use provided values or defaults
      if sep_pre.nil? || sep_pre.to_s.strip.empty?
        sep_pre = ''
      else
        sep_pre = sep_pre.to_s
      end
      
      if sep_post.nil? || sep_post.to_s.strip.empty?
        sep_post = ''
      else
        sep_post = sep_post.to_s
      end
      
      # Format: PRE ITEM POST SEPARATOR PRE ITEM POST...
      formatted_items = items.map do |item|
        "#{item_pre}#{item.to_s}#{item_post}"
      end
      
      # Build separator: sep_pre + separator + sep_post
      separator_wrapped = "#{sep_pre}#{separator}#{sep_post}"
      
      # Join items with separator between them
      formatted_items.join(separator_wrapped)
    end
  end
end

Liquid::Template.register_filter(Jekyll::FormatListFilter)

