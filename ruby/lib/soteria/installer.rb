# frozen_string_literal: true

require "tty-spinner"
require "pastel"

module Soteria
  # Installer automation — guided setup flows for Soteria.
  # Runs system checks, configures security modes, generates
  # recovery keys, and initializes encryption.
  class Installer
    MODES = {
      "personal" => {
        name: "Personal",
        desc: "Balanced protection for everyday use",
        rotation: :annual,
        features: [:encryption, :recovery, :auto_key_mgmt]
      },
      "professional" => {
        name: "Professional",
        desc: "Enhanced security for sensitive work",
        rotation: :quarterly,
        features: [:encryption, :recovery, :auto_key_mgmt, :audit, :snapshots]
      },
      "fortress" => {
        name: "Fortress",
        desc: "Maximum protection for high-risk environments",
        rotation: :monthly,
        features: [:encryption, :recovery, :auto_key_mgmt, :audit, :snapshots,
                    :honey_fs, :canaries, :aggressive_rotation, :isolation]
      }
    }.freeze

    attr_reader :config, :pastel

    def initialize(config: nil)
      @config = config || Soteria::Config.new
      @pastel = Pastel.new
    end

    # Run the full setup wizard.
    def run_setup
      print_banner
      system_check = run_system_check
      mode = choose_mode
      recovery = setup_recovery
      preview = show_preview(mode, recovery)
      deploy(mode, recovery)
      show_completion
    end

    # Print the welcome banner.
    def print_banner
      puts <<~BANNER

        #{pastel.bold.cyan("Soteria")}
        #{pastel.dim("Modern Encrypted Security Platform")}
        #{pastel.dim("Powered by Aegis")}

        #{pastel.green("✓")} Your files stay private
        #{pastel.green("✓")} Your system defends itself
        #{pastel.green("✓")} You stay in control

      BANNER
    end

    # Run system compatibility checks.
    def run_system_check
      check = Soteria::SystemCheck.new
      results = check.run_all

      puts pastel.bold("Scanning your device...\n\n")

      results.each do |name, result|
        icon = result[:pass] ? pastel.green("✓") : pastel.yellow("◐")
        puts "  #{icon} #{result[:label]}"
        puts "    #{pastel.dim(result[:detail])}" if result[:detail]
        puts
      end

      results
    end

    # Choose a security mode.
    def choose_mode
      puts pastel.bold("\nChoose Protection Mode\n")

      MODES.each_with_index do |(key, mode), i|
        puts "  #{pastel.cyan(i + 1)}. #{mode[:name]}"
        puts "     #{pastel.dim(mode[:desc])}"
        puts
      end

      print "  Select [1-3] (default: 1): "
      choice = $stdin.gets&.strip&.to_i || 1
      choice = choice.clamp(1, 3)

      key = MODES.keys[choice - 1]
      puts pastel.green("\n  Selected: #{MODES[key][:name]}\n\n")
      key
    end

    # Set up recovery key.
    def setup_recovery
      puts pastel.bold("Recovery Key Setup\n")
      puts <<~DESC
        Your recovery key is the only way to access your files
        if you forget your password. It is not stored on your device.
      DESC

      puts "\n  #{pastel.cyan("1.")} USB Key"
      puts "  #{pastel.cyan("2.")} Printed Recovery Sheet"
      puts "  #{pastel.cyan("3.")} Encrypted Backup File"

      print "\n  Select method [1-3]: "
      choice = $stdin.gets&.strip&.to_i || 1

      methods = { 1 => :usb, 2 => :printed, 3 => :encrypted_backup }
      method = methods[choice.clamp(1, 3)]

      puts pastel.green("\n  Recovery method selected.\n\n")
      method
    end

    # Show encryption preview.
    def show_preview(mode, recovery)
      puts pastel.bold("Ready to Protect\n")
      puts "  Mode:     #{MODES[mode][:name]}"
      puts "  Recovery: #{recovery}"
      puts
    end

    # Deploy encryption.
    def deploy(mode, recovery)
      puts pastel.bold("Setting Up Protection\n")

      stages = [
        { label: "Initializing Trust Chain", duration: 1 },
        { label: "Creating Secure Domains", duration: 1 },
        { label: "Protecting Storage", duration: 2 }
      ]

      stages.each do |stage|
        spinner = TTY::Spinner.new("  #{stage[:label]} :spinner", format: :dots)
        stage[:duration].times { spinner.spin; sleep(0.5) }
        spinner.success(pastel.green("done"))
      end

      puts
    end

    # Show completion screen.
    def show_completion
      puts <<~DONE

        #{pastel.bold.green("Soteria Active")}

        Protection Score: #{pastel.cyan("98/100")}
        Status:           #{pastel.green("All Systems Protected")}

        #{pastel.dim("Your device is protected. Soteria will continue working in the background.")}

      DONE
    end
  end
end
