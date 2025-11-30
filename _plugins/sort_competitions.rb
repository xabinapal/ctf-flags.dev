require 'date'

module Jekyll
  module SortCompetitionsFilter
    def sort_competitions(competitions)
      Jekyll.logger.debug "SortCompetitions:", "Input received: #{competitions.class}"
      Jekyll.logger.debug "SortCompetitions:", "Is nil?: #{competitions.nil?}"
      Jekyll.logger.debug "SortCompetitions:", "Is array?: #{competitions.is_a?(Array)}"
      
      if competitions.nil?
        Jekyll.logger.warn "SortCompetitions:", "Input is nil, returning empty array"
        return []
      end
      
      unless competitions.is_a?(Array)
        Jekyll.logger.warn "SortCompetitions:", "Input is not an array (#{competitions.class}), returning empty array"
        return []
      end
      
      Jekyll.logger.debug "SortCompetitions:", "Array size: #{competitions.size}"
      
      if competitions.empty?
        Jekyll.logger.debug "SortCompetitions:", "Array is empty, returning as-is"
        return competitions
      end
      
      # Debug first competition structure
      first_comp = competitions.first
      Jekyll.logger.debug "SortCompetitions:", "First competition class: #{first_comp.class}"
      Jekyll.logger.debug "SortCompetitions:", "First competition responds to :data?: #{first_comp.respond_to?(:data)}"
      if first_comp.respond_to?(:data)
        Jekyll.logger.debug "SortCompetitions:", "First competition data keys: #{first_comp.data.keys.inspect}"
      end
      if first_comp.respond_to?(:[])
        Jekyll.logger.debug "SortCompetitions:", "First competition['start_date']: #{first_comp['start_date'].inspect}"
      end
      
      Jekyll.logger.debug "SortCompetitions:", "About to start sorting..."
      
      begin
        sorted = competitions.sort do |a, b|
          Jekyll.logger.debug "SortCompetitions:", "Inside sort block - comparing two competitions"
          
          # Helper to get data from competition object
          get_data = lambda do |comp, key|
            value = if comp.respond_to?(:data)
              comp.data[key]
            elsif comp.respond_to?(:[])
              comp[key]
            else
              Jekyll.logger.warn "SortCompetitions:", "Competition object doesn't respond to :data or :[]: #{comp.class}"
              nil
            end
            value
          end
          
          # Helper to normalize date - handles both Date objects and strings
          normalize_date = lambda do |date_value|
            if date_value.nil?
              Jekyll.logger.debug "SortCompetitions:", "Date value is nil, using far future date"
              Date.new(9999, 12, 31)
            elsif date_value.is_a?(Date)
              Jekyll.logger.debug "SortCompetitions:", "Date value is already a Date object: #{date_value}"
              date_value
            elsif date_value.to_s.strip.empty?
              Jekyll.logger.debug "SortCompetitions:", "Date value is empty string, using far future date"
              Date.new(9999, 12, 31)
            else
              begin
                parsed = Date.parse(date_value.to_s)
                Jekyll.logger.debug "SortCompetitions:", "Parsed date string '#{date_value}' to: #{parsed}"
                parsed
              rescue => e
                Jekyll.logger.warn "SortCompetitions:", "Failed to parse date '#{date_value}': #{e.message}, using far future date"
                Date.new(9999, 12, 31)
              end
            end
          end
          
          # Get dates and title
          a_start_raw = get_data.call(a, 'start_date')
          b_start_raw = get_data.call(b, 'start_date')
          a_end_raw = get_data.call(a, 'end_date')
          b_end_raw = get_data.call(b, 'end_date')
          
          Jekyll.logger.debug "SortCompetitions:", "a.start_date raw: #{a_start_raw.inspect} (#{a_start_raw.class})"
          Jekyll.logger.debug "SortCompetitions:", "b.start_date raw: #{b_start_raw.inspect} (#{b_start_raw.class})"
          
          a_start = normalize_date.call(a_start_raw)
          b_start = normalize_date.call(b_start_raw)
          a_end = normalize_date.call(a_end_raw)
          b_end = normalize_date.call(b_end_raw)
          a_title = (get_data.call(a, 'title') || '').to_s.downcase
          b_title = (get_data.call(b, 'title') || '').to_s.downcase
          
          Jekyll.logger.debug "SortCompetitions:", "a_start: #{a_start}, b_start: #{b_start}"
          Jekyll.logger.debug "SortCompetitions:", "a_end: #{a_end}, b_end: #{b_end}"
          Jekyll.logger.debug "SortCompetitions:", "a_title: #{a_title}, b_title: #{b_title}"
          
          # Primary sort: start_date (REVERSED - newest first)
          start_compare = b_start <=> a_start
          Jekyll.logger.debug "SortCompetitions:", "start_compare: #{start_compare}"
          if start_compare != 0
            start_compare
          else
            # Secondary sort: end_date (REVERSED - newest first)
            end_compare = b_end <=> a_end
            Jekyll.logger.debug "SortCompetitions:", "end_compare: #{end_compare}"
            if end_compare != 0
              end_compare
            else
              # Tertiary sort: title (NOT REVERSED - alphabetical)
              title_compare = a_title <=> b_title
              Jekyll.logger.debug "SortCompetitions:", "title_compare: #{title_compare}"
              title_compare
            end
          end
        end
        
        Jekyll.logger.debug "SortCompetitions:", "Sorting complete, returning #{sorted.size} competitions"
        Jekyll.logger.debug "SortCompetitions:", "Sorted array class: #{sorted.class}"
        Jekyll.logger.debug "SortCompetitions:", "Sorted array is array?: #{sorted.is_a?(Array)}"
        Jekyll.logger.debug "SortCompetitions:", "First sorted competition: #{sorted.first&.data&.dig('title') || 'nil'}"
        result = sorted
        Jekyll.logger.debug "SortCompetitions:", "About to return result, class: #{result.class}, size: #{result.size}"
        result
      rescue => e
        Jekyll.logger.error "SortCompetitions:", "Error during sorting: #{e.message}"
        Jekyll.logger.error "SortCompetitions:", e.backtrace.join("\n")
        # Return original array if sorting fails
        Jekyll.logger.warn "SortCompetitions:", "Returning original unsorted array due to error"
        competitions
      end.tap do |final_result|
        Jekyll.logger.debug "SortCompetitions:", "Final return value class: #{final_result.class}, size: #{final_result.size}"
      end
    end
  end
end

Liquid::Template.register_filter(Jekyll::SortCompetitionsFilter)

