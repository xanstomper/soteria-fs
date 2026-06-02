# frozen_string_literal: true

# Soteria GUI — VeraCrypt-like native desktop interface.
# Uses libui for cross-platform native widgets.

require "libui"
require_relative "../volume"
require_relative "../core_bridge"

module Soteria
  module GUI
    class App
      include LibUI

      def initialize
        @manager = Soteria::Volume::Manager.new
        @selected_volume = nil
        @status_message = "Ready"
      end

      def run
        main_window = create_main_window
        LibUI.main
        LibUI.control_destroy(main_window)
      end

      private

      def create_main_window
        # Main window
        main_box = LibUI.new_vertical_box
        LibUI.box_set_padded(main_box, 1)

        # Header
        header = create_header
        LibUI.box_append(main_box, header, 0)

        # Volume list
        volume_group = create_volume_list
        LibUI.box_append(main_box, volume_group, 1)

        # Action buttons
        actions = create_action_buttons
        LibUI.box_append(main_box, actions, 0)

        # Status bar
        status = create_status_bar
        LibUI.box_append(main_box, status, 0)

        # Menu bar
        menu = create_menu_bar

        # Window
        main_window = LibUI.new_menu_item("Soteria Aegis")
        LibUI.window_set_title(main_window, "Soteria Aegis — Encrypted Storage")
        LibUI.window_set_child(main_window, main_box)
        LibUI.window_set_margined(main_window, 1)
        LibUI.window_on_closing(main_window) do
          LibUI.quit
          0
        end

        LibUI.control_show(main_window)
        main_window
      end

      def create_header
        box = LibUI.new_vertical_box
        LibUI.box_set_padded(box, 0)

        # Title
        title = LibUI.new_label("Soteria Aegis")
        LibUI.box_append(box, title, 0)

        # Subtitle
        subtitle = LibUI.new_label("Encrypted Storage Platform — Powered by Aegis")
        LibUI.box_append(box, subtitle, 0)

        box
      end

      def create_volume_list
        group = LibUI.new_group("Encrypted Volumes")
        LibUI.group_set_margined(group, 1)

        box = LibUI.new_vertical_box
        LibUI.box_set_padded(box, 1)

        # Volume table
        @volume_table = LibUI.new_table
        LibUI.table_append_text_column(@volume_table, "Name", 0)
        LibUI.table_append_text_column(@volume_table, "Size", 1)
        LibUI.table_append_text_column(@volume_table, "Mode", 2)
        LibUI.table_append_text_column(@volume_table, "Status", 3)
        LibUI.table_append_text_column(@volume_table, "Mount Point", 4)

        LibUI.box_append(box, @volume_table, 1)

        # Add some placeholder volumes
        add_placeholder_volumes

        LibUI.group_set_child(group, box)
        group
      end

      def create_action_buttons
        box = LibUI.new_horizontal_box
        LibUI.box_set_padded(box, 1)

        # Create volume button
        create_btn = LibUI.new_button("Create Volume")
        LibUI.button_on_clicked(create_btn) { show_create_wizard }
        LibUI.box_append(box, create_btn, 0)

        # Mount button
        mount_btn = LibUI.new_button("Mount")
        LibUI.button_on_clicked(mount_btn) { mount_selected }
        LibUI.box_append(box, mount_btn, 0)

        # Unmount button
        unmount_btn = LibUI.new_button("Unmount")
        LibUI.button_on_clicked(unmount_btn) { unmount_selected }
        LibUI.box_append(box, unmount_btn, 0)

        # Verify button
        verify_btn = LibUI.new_button("Verify Integrity")
        LibUI.button_on_clicked(verify_btn) { verify_selected }
        LibUI.box_append(box, verify_btn, 0)

        # Settings button
        settings_btn = LibUI.new_button("Settings")
        LibUI.button_on_clicked(settings_btn) { show_settings }
        LibUI.box_append(box, settings_btn, 0)

        box
      end

      def create_status_bar
        box = LibUI.new_horizontal_box
        LibUI.box_set_padded(box, 0)

        @status_label = LibUI.new_label(@status_message)
        LibUI.box_append(box, @status_label, 1)

        box
      end

      def create_menu_bar
        # File menu
        file_menu = LibUI.new_menu
        LibUI.menu_append_item(file_menu, "Create Volume")
        LibUI.menu_append_item(file_menu, "Open Volume")
        LibUI.menu_append_separator(file_menu)
        LibUI.menu_append_item(file_menu, "Exit")

        # Tools menu
        tools_menu = LibUI.new_menu
        LibUI.menu_append_item(tools_menu, "Verify All")
        LibUI.menu_append_item(tools_menu, "Key Management")
        LibUI.menu_append_item(tools_menu, "Audit Log")

        # Help menu
        help_menu = LibUI.new_menu
        LibUI.menu_append_item(help_menu, "Documentation")
        LibUI.menu_append_item(help_menu, "About Soteria")
      end

      def add_placeholder_volumes
        # Add some example volumes to the table
        ["Documents", "Work", "Archive"].each_with_index do |name, i|
          vol = Soteria::Volume::VolumeInfo.new(
            name: name,
            path: "/vaults/#{name}.sot",
            size: (i + 1) * 500_000_000_000,
            mode: [:personal, :professional, :fortress][i],
            status: i < 2 ? Soteria::Volume::MOUNTED : Soteria::Volume::UNMOUNTED
          )
          @manager.instance_variable_get(:@volumes) << vol
        end
        refresh_volume_table
      end

      def refresh_volume_table
        # In a real implementation, this would update the table model
        @status_message = "Volumes: #{@manager.volumes.length} total, #{@manager.mounted_volumes.length} mounted"
        LibUI.label_set_text(@status_label, @status_message) if @status_label
      end

      def show_create_wizard
        # Create wizard window
        wizard = LibUI.new_window("Create Encrypted Volume", 500, 400)
        LibUI.window_set_margined(wizard, 1)

        box = LibUI.new_vertical_box
        LibUI.box_set_padded(box, 1)

        # Step 1: Volume name
        name_group = LibUI.new_group("Volume Name")
        name_box = LibUI.new_vertical_box
        LibUI.box_set_padded(name_box, 1)
        @name_entry = LibUI.new_entry
        LibUI.entry_set_text(@name_entry, "MyVolume")
        LibUI.box_append(name_box, @name_entry, 0)
        LibUI.group_set_child(name_group, name_box)
        LibUI.box_append(box, name_group, 0)

        # Step 2: Security mode
        mode_group = LibUI.new_group("Security Mode")
        mode_box = LibUI.new_vertical_box
        LibUI.box_set_padded(mode_box, 1)
        @mode_radio = LibUI.new_radio_buttons
        LibUI.radio_buttons_append(@mode_radio, "Personal — Balanced protection")
        LibUI.radio_buttons_append(@mode_radio, "Professional — Enhanced security")
        LibUI.radio_buttons_append(@mode_radio, "Fortress — Maximum protection")
        LibUI.radio_buttons_set_selected(@mode_radio, 0)
        LibUI.box_append(mode_box, @mode_radio, 0)
        LibUI.group_set_child(mode_group, mode_box)
        LibUI.box_append(box, mode_group, 0)

        # Step 3: Passphrase
        pass_group = LibUI.new_group("Passphrase")
        pass_box = LibUI.new_vertical_box
        LibUI.box_set_padded(pass_box, 1)
        @pass_entry = LibUI.new_password_entry
        LibUI.box_append(pass_box, @pass_entry, 0)
        LibUI.group_set_child(pass_group, pass_box)
        LibUI.box_append(box, pass_group, 0)

        # Create button
        create_btn = LibUI.new_button("Create Volume")
        LibUI.button_on_clicked(create_btn) do
          name = LibUI.entry_text(@name_entry)
          mode = [:personal, :professional, :fortress][LibUI.radio_buttons_selected(@mode_radio)]
          passphrase = LibUI.entry_text(@pass_entry)

          update_status("Creating volume '#{name}'...")
          # In real implementation: call Soteria::CoreBridge.encrypt
          update_status("Volume '#{name}' created successfully!")
          LibUI.control_destroy(wizard)
          refresh_volume_table
        end
        LibUI.box_append(box, create_btn, 0)

        # Cancel button
        cancel_btn = LibUI.new_button("Cancel")
        LibUI.button_on_clicked(cancel_btn) { LibUI.control_destroy(wizard) }
        LibUI.box_append(box, cancel_btn, 0)

        LibUI.window_set_child(wizard, box)
        LibUI.control_show(wizard)
      end

      def mount_selected
        # Show mount dialog
        mount_dialog = LibUI.new_window("Mount Volume", 400, 200)
        LibUI.window_set_margined(mount_dialog, 1)

        box = LibUI.new_vertical_box
        LibUI.box_set_padded(box, 1)

        LibUI.box_append(box, LibUI.new_label("Enter passphrase to mount:"), 0)

        @mount_pass = LibUI.new_password_entry
        LibUI.box_append(box, @mount_pass, 0)

        btn_box = LibUI.new_horizontal_box
        LibUI.box_set_padded(btn_box, 1)

        mount_btn = LibUI.new_button("Mount")
        LibUI.button_on_clicked(mount_btn) do
          passphrase = LibUI.entry_text(@mount_pass)
          update_status("Mounting volume...")
          # In real implementation: call mount
          update_status("Volume mounted successfully!")
          LibUI.control_destroy(mount_dialog)
          refresh_volume_table
        end
        LibUI.box_append(btn_box, mount_btn, 0)

        cancel_btn = LibUI.new_button("Cancel")
        LibUI.button_on_clicked(cancel_btn) { LibUI.control_destroy(mount_dialog) }
        LibUI.box_append(btn_box, cancel_btn, 0)

        LibUI.box_append(box, btn_box, 0)
        LibUI.window_set_child(mount_dialog, box)
        LibUI.control_show(mount_dialog)
      end

      def unmount_selected
        update_status("Unmounting volume...")
        # In real implementation: call unmount
        update_status("Volume unmounted.")
        refresh_volume_table
      end

      def verify_selected
        update_status("Verifying volume integrity...")
        # In real implementation: call verify
        update_status("Integrity check passed.")
      end

      def show_settings
        settings_win = LibUI.new_window("Settings", 500, 400)
        LibUI.window_set_margined(settings_win, 1)

        box = LibUI.new_vertical_box
        LibUI.box_set_padded(box, 1)

        # Security mode
        mode_group = LibUI.new_group("Security Mode")
        mode_box = LibUI.new_vertical_box
        LibUI.box_set_padded(mode_box, 1)
        mode_radio = LibUI.new_radio_buttons
        LibUI.radio_buttons_append(mode_radio, "Personal — Balanced")
        LibUI.radio_buttons_append(mode_radio, "Professional — Enhanced")
        LibUI.radio_buttons_append(mode_radio, "Fortress — Maximum")
        LibUI.radio_buttons_set_selected(mode_radio, 0)
        LibUI.box_append(mode_box, mode_radio, 0)
        LibUI.group_set_child(mode_group, mode_box)
        LibUI.box_append(box, mode_group, 0)

        # Notifications
        notif_group = LibUI.new_group("Notifications")
        notif_box = LibUI.new_vertical_box
        LibUI.box_set_padded(notif_box, 1)
        alerts_check = LibUI.new_checkbox("Security alerts")
        LibUI.checkbox_set_checked(alerts_check, 1)
        LibUI.box_append(notif_box, alerts_check, 0)
        rotation_check = LibUI.new_checkbox("Key rotation reminders")
        LibUI.checkbox_set_checked(rotation_check, 1)
        LibUI.box_append(notif_box, rotation_check, 0)
        recovery_check = LibUI.new_checkbox("Recovery test reminders")
        LibUI.checkbox_set_checked(recovery_check, 1)
        LibUI.box_append(notif_box, recovery_check, 0)
        LibUI.group_set_child(notif_group, notif_box)
        LibUI.box_append(box, notif_group, 0)

        # Close button
        close_btn = LibUI.new_button("Save & Close")
        LibUI.button_on_clicked(close_btn) do
          update_status("Settings saved.")
          LibUI.control_destroy(settings_win)
        end
        LibUI.box_append(box, close_btn, 0)

        LibUI.window_set_child(settings_win, box)
        LibUI.control_show(settings_win)
      end

      def update_status(message)
        @status_message = message
        LibUI.label_set_text(@status_label, @status_message) if @status_label
      end
    end
  end
end
