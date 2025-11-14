module Jekyll
  module GroupByCategoryFilter
    def group_by_category(writeups)
      return [] if writeups.nil? || !writeups.is_a?(Array)
      
      grouped = {}
      
      writeups.each do |writeup|
        # Access front matter data - try both hash and data method access
        category = writeup.respond_to?(:data) ? writeup.data['challenge_type'] : writeup['challenge_type']
        category = category.to_s.strip if category
        category = 'uncategorized' if category.nil? || category.empty?
        
        grouped[category] ||= []
        grouped[category] << writeup
      end
      
      # Sort each category's writeups
      grouped.each do |category, items|
        grouped[category] = items.sort_by do |item|
          title = item.respond_to?(:data) ? item.data['title'] : item['title']
          title.to_s
        end
      end
      
      # Return array of hashes with 'category' and 'writeups' keys, sorted by category name
      grouped.sort.map do |category, items|
        { 'category' => category, 'writeups' => items }
      end
    end
  end
end

Liquid::Template.register_filter(Jekyll::GroupByCategoryFilter)

