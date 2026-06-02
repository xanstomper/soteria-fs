# frozen_string_literal: true

require_relative "lib/soteria/version"

Gem::Specification.new do |spec|
  spec.name = "soteria"
  spec.version = Soteria::VERSION
  spec.authors = ["Soteria Team"]
  spec.email = ["team@soteria.dev"]

  spec.summary = "Ruby tooling for the Soteria encrypted security platform"
  spec.description = <<~DESC
    Administrative CLI, installer automation, and orchestration tools for
    Soteria — a hardware-rooted encrypted security platform built in Rust.
    Ruby handles scripting, packaging, admin workflows, and system
    automation. The cryptographic core is in Rust (soteria-core).
  DESC
  spec.homepage = "https://github.com/xanstomper/soteria-fs"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.files = Dir["lib/**/*.rb", "bin/*", "tasks/*.rake", "README.md", "LICENSE"]
  spec.bindir = "bin"
  spec.executables = ["soteria", "soteria-install", "soteria-admin"]

  spec.add_dependency "thor", "~> 1.3"
  spec.add_dependency "paint", "~> 2.3"
  spec.add_dependency "tty-spinner", "~> 0.9"
  spec.add_dependency "tty-table", "~> 0.12"
  spec.add_dependency "pastel", "~> 0.8"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rubocop", "~> 1.60"
end
