module Jekyll
  module TruncateWordsFilter
    def truncate_words(input, max_chars = 160)
      return '' if input.nil? || input.to_s.strip.empty?

      text = input.to_s.strip
      words = text.split(/\s+/)
      return text if words.empty?

      result = []
      char_count = 0

      words.each_with_index do |word, index|
        # Calculate the character count if we add this word
        # Add 1 for space if not the first word
        test_count = char_count == 0 ? word.length : char_count + 1 + word.length

        # If adding this word would exceed the limit and it's not the last word, stop
        if test_count > max_chars && index < words.length - 1
          return result.join(' ') + '...'
        end

        # Add the word
        if char_count == 0
          result << word
          char_count = word.length
        else
          result << word
          char_count = test_count
        end
      end

      # Return the full text if we didn't truncate
      result.join(' ')
    end
  end
end

Liquid::Template.register_filter(Jekyll::TruncateWordsFilter)

