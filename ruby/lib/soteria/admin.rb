# frozen_string_literal: true

require "tty-table"
require "pastel"

module Soteria
  # Administrative tools for managing Soteria deployments.
  # These are the Ruby-based admin utilities that complement
  # the Rust CLI with higher-level workflows.
  class Admin
    attr_reader :pastel

    def initialize
      @pastel = Pastel.new
    end

    # Show system status overview.
    def status
      puts pastel.bold("Soteria System Status\n")

      checks = [
        { name: "Binary", value: Soteria.binary_available? ? "Found" : "Not found",
          ok: Soteria.binary_available? },
        { name: "TPM", value: tpm_status, ok: true },
        { name: "Version", value: Soteria::VERSION, ok: true }
      ]

      table = TTY::Table.new(
        header: ["Component", "Status", "Health"],
        rows: checks.map { |c| [c[:name], c[:value], c[:ok] ? "✓" : "✗"] }
      )
      puts table.render(:unicode, padding: [0, 1, 0, 1])
      puts
    end

    # Run a health check on all volumes.
    def health_check(dir)
      puts pastel.bold("Health Check: #{dir}\n")

      unless Soteria.binary_available?
        puts pastel.red("  soteriad binary not found. Run: cd rust-core && cargo build --release")
        return
      end

      result = Soteria::CoreBridge.verify(dir: dir)
      if result["ok"]
        puts pastel.green("  All volumes pass integrity verification.")
      else
        puts pastel.red("  Integrity check failed!")
        puts "  #{result.inspect}"
      end
    end

    # Generate a report of all keys and their status.
    def key_report
      puts pastel.bold("Key Lifecycle Report\n")
      puts pastel.dim("  (Key data is managed by the Rust core)")
      puts pastel.dim("  Run: soteriad keygen --help")
      puts
    end

    # Export audit log to a file.
    def export_audit(log_path, output_path)
      puts pastel.bold("Exporting Audit Log\n")

      result = Soteria::CoreBridge.audit(log: log_path, verify_only: false)
      File.write(output_path, JSON.pretty_generate(result))
      puts pastel.green("  Exported to: #{output_path}")
    end

    # Batch encrypt multiple files.
    def batch_encrypt(files, into:, passphrase:, fast_kdf: false)
      puts pastel.bold("Batch Encrypting #{files.length} files\n")

      files.each_with_index do |file, i|
        name = File.basename(file, ".*")
        puts "  [#{i + 1}/#{files.length}] #{name}..."
        Soteria::CoreBridge.encrypt(
          src: file, into: into, name: name,
          passphrase: passphrase, fast_kdf: fast_kdf
        )
        puts pastel.green("    ✓ done")
      rescue Soteria::Error => e
        puts pastel.red("    ✗ #{e.message}")
      end

      puts
    end

    # Batch decrypt multiple files.
    def batch_decrypt(volumes, from:, passphrase:, output_dir:)
      puts pastel.bold("Batch Decrypting #{volumes.length} volumes\n")

      volumes.each_with_index do |name, i|
        output = File.join(output_dir, "#{name}.decrypted")
        puts "  [#{i + 1}/#{volumes.length}] #{name}..."
        Soteria::CoreBridge.decrypt(
          from: from, name: name,
          passphrase: passphrase, output: output
        )
        puts pastel.green("    ✓ done")
      rescue Soteria::Error => e
        puts pastel.red("    ✗ #{e.message}")
      end

      puts
    end

    private

    def tpm_status
      # Check for TPM availability without calling the binary.
      if File.exist?("/dev/tpmrm0") || File.exist?("/dev/tpm0")
        "Hardware TPM2 detected"
      elsif Gem.win_platform?
        "Windows TBS (check Device Manager)"
      else
        "Software fallback"
      end
    end
  end
end
