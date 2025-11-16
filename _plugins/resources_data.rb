module Jekyll
  class ResourcesDataGenerator < Generator
    safe true
    priority :high

    def generate(site)
      resources_dir = File.join(site.source, '_resources')
      return unless Dir.exist?(resources_dir)

      site.data['resources'] ||= {}

      Dir.glob(File.join(resources_dir, '*.yml')).each do |file|
        category = File.basename(file, '.yml')
        begin
          resources = YAML.load_file(file)
          site.data['resources'][category] = resources
        rescue => e
          Jekyll.logger.warn "Resources Data:", "Error loading #{file}: #{e.message}"
        end
      end
    end
  end
end

