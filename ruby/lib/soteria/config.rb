# frozen_string_literal: true

require "toml-rb"

module Soteria
  # Configuration management for Soteria.
  # Reads/writes the soteria.toml config file and provides
  # defaults for all settings.
  class Config
    DEFAULTS = {
      "crypto" => {
        "algorithm" => "xchacha20-poly1305",
        "block_size" => 65536,
        "argon2_memory_kib" => 19_456,
        "argon2_iterations" => 2
      },
      "key_lifecycle" => {
        "session_ttl_seconds" => 3600,
        "ratchet_every_events" => 100,
        "enforce_zeroize" => true
      },
      "fuse" => {
        "flush_interval_secs" => 30,
        "read_cache_mb" => 64
      }
    }.freeze

    attr_reader :data, :path

    def initialize(path = nil)
      @path = path || default_config_path
      @data = load_config
    end

    def [](key)
      @data[key]
    end

    def []=(key, value)
      @data[key] = value
    end

    def save
      File.write(@path, TOML::Generator.new(@data).body)
    end

    def to_h
      @data.dup
    end

    private

    def default_config_path
      # Try project root first, then system config.
      project_path = File.expand_path("../../config/soteria.toml", __dir__)
      return project_path if File.exist?(project_path)

      if Gem.win_platform?
        File.join(ENV["APPDATA"] || "C:/", "Soteria", "soteria.toml")
      else
        "/etc/soteria/soteria.toml"
      end
    end

    def load_config
      if File.exist?(@path)
        TOML::Parser.new(@path).parsed.merge(DEFAULTS) { |_, new_val, _| new_val }
      else
        DEFAULTS.dup
      end
    rescue => e
      $stderr.puts "Warning: failed to load config from #{@path}: #{e.message}"
      DEFAULTS.dup
    end
  end
end
