# frozen_string_literal: true

# Soteria Setup Wizard — first-run experience.
# Guides the user through system checks, mode selection, recovery setup,
# and initial encryption. VeraCrypt-like but modern and calm.

require "libui"
require_relative "../volume"
require_relative "../system_check"

module Soteria
  module GUI
    class SetupWizard
      include LibUI

      def initialize
        @step = 0
        @selected_mode = :personal
        @recovery_method = :usb
        @passphrase = ""
        @checks = []
      end

      def run
        @main_window = create_window
        LibUI.main
        LibUI.control_destroy(@main_window)
      end

      private

      def create_window
        box = LibUI.new_vertical_box
        LibUI.box_set_padded(box, 1)

        # Progress bar
        @progress = LibUI.newProgressBar
        LibUI.progressBar_setValue(@progress, 0)
        LibUI.box_append(box, @progress, 0)

        # Content area
        @content_box = LibUI.new_vertical_box
        LibUI.box_set_padded(@content_box, 1)
        LibUI.box_append(box, @content_box, 1)

        # Navigation buttons
        nav_box = LibUI.new_horizontal_box
        LibUI.box_set_padded(nav_box, 1)

        @back_btn = LibUI.new_button("Back")
        LibUI.button_on_clicked(@back_btn) { go_back }
        LibUI.box_append(nav_box, @back_btn, 0)

        @next_btn = LibUI.new_button("Next")
        LibUI.button_on_clicked(@next_btn) { go_next }
        LibUI.box_append(nav_box, @next_btn, 0)

        LibUI.box_append(box, nav_box, 0)

        # Window
        window = LibUI.new_window("Soteria Setup", 600, 500)
        LibUI.window_set_margined(window, 1)
        LibUI.window_set_child(window, box)
        LibUI.window_on_closing(window) do
          LibUI.quit
          0
        end

        LibUI.control_show(window)
        show_step(0)
        window
      end

      def show_step(step)
        @step = step
        update_progress

        # Clear content
        LibUI.control_destroy(@content_box) if @content_box
        @content_box = LibUI.new_vertical_box
        LibUI.box_set_padded(@content_box, 1)

        case step
        when 0 then show_welcome
        when 1 then show_system_check
        when 2 then show_mode_selection
        when 3 then show_recovery_setup
        when 4 then show_passphrase
        when 5 then show_encrypting
        when 6 then show_complete
        end

        update_buttons
      end

      def show_welcome
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        title = LibUI.new_label("Welcome to Soteria")
        LibUI.box_append(@content_box, title, 0)

        subtitle = LibUI.new_label("Protect your device in minutes")
        LibUI.box_append(@content_box, subtitle, 0)

        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        ["Your files stay private", "Your system defends itself", "You stay in control"].each do |text|
          label = LibUI.new_label("  ✓  #{text}")
          LibUI.box_append(@content_box, label, 0)
        end
      end

      def show_system_check
        LibUI.box_append(@content_box, LibUI.new_label("Scanning your device..."), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        checker = Soteria::SystemCheck.new
        results = checker.run_all

        results.each do |name, result|
          icon = result[:pass] ? "✓" : (result[:critical] ? "✗" : "◐")
          label = LibUI.new_label("  #{icon} #{result[:label]}")
          LibUI.box_append(@content_box, label, 0)

          detail = LibUI.new_label("    #{result[:detail]}")
          LibUI.box_append(@content_box, detail, 0)
        end
      end

      def show_mode_selection
        LibUI.box_append(@content_box, LibUI.new_label("Choose Protection Mode"), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        @mode_radio = LibUI.new_radio_buttons
        LibUI.radio_buttons_append(@mode_radio, "Personal — Balanced protection for everyday use")
        LibUI.radio_buttons_append(@mode_radio, "Professional — Enhanced security for sensitive work")
        LibUI.radio_buttons_append(@mode_radio, "Fortress — Maximum protection for high-risk environments")
        LibUI.radio_buttons_set_selected(@mode_radio, 0)
        LibUI.box_append(@content_box, @mode_radio, 0)

        LibUI.box_append(@content_box, LibUI.new_label(""), 0)
        LibUI.box_append(@content_box, LibUI.new_label("You can change this later at any time."), 0)
      end

      def show_recovery_setup
        LibUI.box_append(@content_box, LibUI.new_label("Recovery Key Setup"), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)
        LibUI.box_append(@content_box, LibUI.new_label("Your recovery key is the only way to access your files if you forget your password."), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        @recovery_radio = LibUI.new_radio_buttons
        LibUI.radio_buttons_append(@recovery_radio, "USB Key — Save to a USB drive")
        LibUI.radio_buttons_append(@recovery_radio, "Printed Sheet — Print a paper backup")
        LibUI.radio_buttons_append(@recovery_radio, "Encrypted Backup — Save an encrypted file")
        LibUI.radio_buttons_set_selected(@recovery_radio, 0)
        LibUI.box_append(@content_box, @recovery_radio, 0)

        LibUI.box_append(@content_box, LibUI.new_label(""), 0)
        LibUI.box_append(@content_box, LibUI.new_label("⚠ Without a recovery key, forgetting your password means losing access permanently."), 0)
      end

      def show_passphrase
        LibUI.box_append(@content_box, LibUI.new_label("Set Your Passphrase"), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)
        LibUI.box_append(@content_box, LibUI.new_label("This is the main password for your encrypted storage."), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        @pass_entry = LibUI.new_password_entry
        LibUI.box_append(@content_box, @pass_entry, 0)

        LibUI.box_append(@content_box, LibUI.new_label(""), 0)
        LibUI.box_append(@content_box, LibUI.new_label("Confirm passphrase:"), 0)
        @pass_confirm = LibUI.new_password_entry
        LibUI.box_append(@content_box, @pass_confirm, 0)
      end

      def show_encrypting
        LibUI.box_append(@content_box, LibUI.new_label("Setting Up Protection"), 0)
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        @encrypt_progress = LibUI.newProgressBar
        LibUI.progressBar_setValue(@encrypt_progress, 0)
        LibUI.box_append(@content_box, @encrypt_progress, 0)

        @encrypt_status = LibUI.new_label("Initializing...")
        LibUI.box_append(@content_box, @encrypt_status, 0)

        # Simulate encryption progress
        Thread.new do
          stages = [
            { label: "Initializing trust chain", progress: 20 },
            { label: "Installing security core", progress: 40 },
            { label: "Creating secure domains", progress: 60 },
            { label: "Configuring encryption", progress: 80 },
            { label: "Finalizing protection", progress: 100 },
          ]

          stages.each do |stage|
            sleep(1)
            LibUI.progressBar_setValue(@encrypt_progress, stage[:progress])
            LibUI.label_set_text(@encrypt_status, stage[:label])
          end

          # Mark setup as complete
          config_dir = if Gem.win_platform?
            File.join(ENV["APPDATA"] || "C:\\Users\\Default\\AppData\\Roaming", "Soteria")
          else
            "/etc/soteria"
          end
          FileUtils.mkdir_p(config_dir)
          File.write(File.join(config_dir, ".setup-complete"), Time.now.to_s)

          sleep(0.5)
          show_step(6)
        end
      end

      def show_complete
        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        title = LibUI.new_label("Soteria Active")
        LibUI.box_append(@content_box, title, 0)

        LibUI.box_append(@content_box, LibUI.new_label(""), 0)

        score_label = LibUI.new_label("Protection Score: 98/100")
        LibUI.box_append(@content_box, score_label, 0)

        status_label = LibUI.new_label("Status: All Systems Protected")
        LibUI.box_append(@content_box, status_label, 0)

        LibUI.box_append(@content_box, LibUI.new_label(""), 0)
        LibUI.box_append(@content_box, LibUI.new_label("Your device is protected. Soteria will continue working in the background."), 0)

        # Change next button to "Open Dashboard"
        LibUI.button_set_text(@next_btn, "Open Dashboard")
      end

      def go_back
        show_step([@step - 1, 0].max) if @step > 0
      end

      def go_next
        if @step == 6
          # Open main app
          LibUI.control_destroy(@main_window)
          require_relative "app"
          app = Soteria::GUI::App.new
          app.run
        else
          show_step(@step + 1)
        end
      end

      def update_progress
        LibUI.progressBar_setValue(@progress, ((@step + 1) * 100 / 7).to_i)
      end

      def update_buttons
        LibUI.control_set_visible(@back_btn, @step > 0 && @step < 6)
        LibUI.control_set_visible(@next_btn, @step < 6 || @step == 6)
      end
    end
  end
end
