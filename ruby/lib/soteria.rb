# frozen_string_literal: true

require_relative "soteria/version"
require_relative "soteria/core_bridge"
require_relative "soteria/installer"
require_relative "soteria/admin"
require_relative "soteria/config"
require_relative "soteria/system_check"

module Soteria
  class Error < StandardError; end

  # Path to the Rust binary.
  def self.binary_path
    @binary_path ||= begin
      path = File.expand_path("../../rust-core/target/release/soteriad", __dir__)
      path += ".exe" if Gem.win_platform?
      path
    end
  end

  # Check if the Rust binary is available.
  def self.binary_available?
    File.exist?(binary_path)
  end
end
