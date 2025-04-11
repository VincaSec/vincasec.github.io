# frozen_string_literal: true

require 'jekyll-watch'

module Jekyll
  module Watcher
    extend self
    
    # Alias the original `listen_ignore_paths` method
    alias_method :original_listen_ignore_paths, :listen_ignore_paths

    # Override `listen_ignore_paths` to add custom ignored paths
    def listen_ignore_paths(options)
      # Add the custom ignore paths to the existing ones
      paths = original_listen_ignore_paths(options)
      
      # Return the updated list of paths, ignoring .TMP files
      paths + [%r!.*\.TMP!i]
    end
  end
end
