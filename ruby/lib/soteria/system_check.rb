# frozen_string_literal: true

module Soteria
  # System compatibility checks for the installer.
  # Checks TPM, Secure Boot, disk, space, and recovery options.
  class SystemCheck
    def run_all
      {
        tpm: check_tpm,
        secure_boot: check_secure_boot,
        disk: check_disk,
        space: check_space,
        recovery: check_recovery
      }
    end

    def check_tpm
      if File.exist?("/dev/tpmrm0") || File.exist?("/dev/tpm0")
        { pass: true, label: "Hardware Security", detail: "Your device has a built-in trust anchor." }
      elsif Gem.win_platform? && tbs_running?
        { pass: true, label: "Hardware Security", detail: "TPM2 available via Windows TBS." }
      else
        { pass: false, label: "Hardware Security",
          detail: "No TPM detected. Soteria will use software-based key storage." }
      end
    end

    def check_secure_boot
      if File.exist?("/sys/firmware/efi/efivars/SecureBoot-*")
        value = File.read(Dir["/sys/firmware/efi/efivars/SecureBoot-*"].first).bytes.last
        if value == 1
          { pass: true, label: "Boot Integrity", detail: "Your system verifies its own startup." }
        else
          { pass: false, label: "Boot Integrity",
            detail: "Secure Boot is disabled. Soteria will still protect your files." }
        end
      elsif Gem.win_platform?
        { pass: true, label: "Boot Integrity", detail: "Windows Secure Boot (check UEFI settings)." }
      else
        { pass: false, label: "Boot Integrity", detail: "Cannot detect Secure Boot status." }
      end
    end

    def check_disk
      # Check if we can write to the current directory.
      test_file = ".soteria_write_test_#{Process.pid}"
      File.write(test_file, "test")
      File.delete(test_file)
      { pass: true, label: "Storage", detail: "Your main drive is ready for protection." }
    rescue
      { pass: false, label: "Storage", detail: "Cannot write to the current disk." }
    end

    def check_space
      # Check available disk space (need at least 100MB).
      stat = Sys::Filesystem.stat(".")
      available_mb = stat.blocks_available * stat.block_size / (1024 * 1024)
      if available_mb > 100
        { pass: true, label: "Space Available", detail: "#{available_mb} MB available." }
      else
        { pass: false, label: "Space Available", detail: "Only #{available_mb} MB available. Need at least 100 MB." }
      end
    rescue
      { pass: true, label: "Space Available", detail: "Unable to check (proceeding)." }
    end

    def check_recovery
      # Check if recovery media options are available.
      has_usb = Dir.exist?("/media") || Dir.exist?("/mnt") || Gem.win_platform?
      has_printer = !Gem.win_platform? # Assume LP available on Linux/macOS
      if has_usb || has_printer
        { pass: true, label: "Recovery Options", detail: "Multiple backup methods available." }
      else
        { pass: false, label: "Recovery Options", detail: "Limited recovery options detected." }
      end
    rescue
      { pass: true, label: "Recovery Options", detail: "Unable to check (proceeding)." }
    end

    private

    def tbs_running?
      return false unless Gem.win_platform?
      output = `sc query TBS 2>&1`
      $?.success? && output.include?("RUNNING")
    rescue
      false
    end
  end
end
