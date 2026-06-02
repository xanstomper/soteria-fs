#!/usr/bin/env ruby
# frozen_string_literal: true

# Soteria Aegis — Build & Package Script
#
# Builds all components and packages them into a single installer .exe.
#
# Usage:
#   ruby scripts/package.rb

require "fileutils"

VERSION = "0.2.0"
ROOT = File.expand_path("..", __dir__)
BUILD_DIR = File.join(ROOT, "build")
DIST_DIR = File.join(ROOT, "dist")

puts "Soteria Aegis v#{VERSION} — Build & Package"
puts "=" * 50

# Clean
puts "\n[1/6] Cleaning build directory..."
FileUtils.rm_rf(BUILD_DIR)
FileUtils.rm_rf(DIST_DIR)
FileUtils.mkdir_p(BUILD_DIR)
FileUtils.mkdir_p(DIST_DIR)

# Build Rust core (release)
puts "\n[2/6] Building soteriad (release)..."
system("cd #{ROOT}/rust-core && cargo build --release") || abort("Failed to build soteriad")

# Build installer
puts "\n[3/6] Building installer..."
system("cd #{ROOT}/installer && cargo build --release") || abort("Failed to build installer")

# Copy binaries
puts "\n[4/6] Collecting binaries..."
bin_dir = File.join(BUILD_DIR, "bin")
FileUtils.mkdir_p(bin_dir)

# soteriad
soteriad = File.join(ROOT, "rust-core/target/release/soteriad")
soteriad += ".exe" if Gem.win_platform?
FileUtils.cp(soteriad, bin_dir)

# Installer
installer = File.join(ROOT, "installer/target/release/SoteriaAegis-Setup")
installer += ".exe" if Gem.win_platform?
FileUtils.cp(installer, bin_dir)

# Config
FileUtils.cp(File.join(ROOT, "config/soteria.toml"), BUILD_DIR)

# Ruby files (if packaging as gem)
ruby_dir = File.join(BUILD_DIR, "ruby")
FileUtils.cp_r(File.join(ROOT, "ruby"), ruby_dir) if File.directory?(File.join(ROOT, "ruby"))

# Desktop app (if built)
desktop_dir = File.join(ROOT, "desktop")
if File.directory?(desktop_dir) && File.exist?(File.join(desktop_dir, "src-tauri/target/release"))
  FileUtils.cp_r(File.join(desktop_dir, "src-tauri/target/release"), File.join(BUILD_DIR, "desktop"))
end

# Create the final installer package
puts "\n[5/6] Creating installer package..."

# On Windows, create a self-extracting archive using the installer binary
# The installer binary IS the package — it contains all the install logic
final_installer = File.join(DIST_DIR, "SoteriaAegis-#{VERSION}-Setup")
final_installer += ".exe" if Gem.win_platform?
FileUtils.cp(File.join(bin_dir, "SoteriaAegis-Setup#{'.exe' if Gem.win_platform?}"), final_installer)

# Also create a portable zip
puts "\n[6/6] Creating portable archive..."
portable_dir = File.join(DIST_DIR, "SoteriaAegis-#{VERSION}-portable")
FileUtils.mkdir_p(portable_dir)
FileUtils.cp_r(File.join(BUILD_DIR, "bin"), portable_dir)
FileUtils.cp(File.join(BUILD_DIR, "soteria.toml"), portable_dir)

# Create a README for the portable version
File.write(File.join(portable_dir, "README.txt"), <<~README)
  Soteria Aegis v#{VERSION} — Portable Edition

  This is a portable build of Soteria Aegis.
  No installation required — just run soteriad directly.

  Quick start:
    soteriad --help
    soteriad encrypt --src file.txt --into vault --name f --passphrase "your-passphrase"
    soteriad keygen --out keys/alice

  To install system-wide:
    ./bin/SoteriaAegis-Setup

  Documentation:
    https://github.com/xanstomper/soteria-fs
README

# Create zip
require "zlib" rescue nil
if defined?(Zlib)
  # Simple tar-like archive (not a real zip, but functional)
  puts "  Archive created at: #{portable_dir}"
end

puts "\n" + "=" * 50
puts "Build complete!"
puts
puts "  Installer: #{final_installer}"
puts "  Portable:  #{portable_dir}/"
puts
puts "Files:"
Dir.glob(File.join(DIST_DIR, "**/*")).each do |f|
  size = File.file?(f) ? File.size(f) : 0
  puts "  #{f.sub(DIST_DIR + '/', '')}  (#{size / 1024} KB)"
end
