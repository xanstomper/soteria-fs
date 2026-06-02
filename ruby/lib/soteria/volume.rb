# frozen_string_literal: true

# Soteria Volume Manager — VeraCrypt-like volume operations.
# Handles creation, mounting, unmounting, and status of encrypted volumes.

module Soteria
  module Volume
    # Volume status
    MOUNTED = "mounted"
    UNMOUNTED = "unmounted"
    CREATING = "creating"
    ERROR = "error"

    # Security modes
    MODES = {
      personal: { name: "Personal", kdf_memory: 19_456, kdf_iterations: 2, description: "Balanced protection for everyday use" },
      professional: { name: "Professional", kdf_memory: 65_536, kdf_iterations: 3, description: "Enhanced security for sensitive work" },
      fortress: { name: "Fortress", kdf_memory: 1_048_576, kdf_iterations: 5, description: "Maximum protection for high-risk environments" },
    }.freeze

    # Represents a single encrypted volume.
    class VolumeInfo
      attr_reader :name, :path, :size, :mode, :status, :mount_point, :created_at

      def initialize(attrs = {})
        @name = attrs[:name]
        @path = attrs[:path]
        @size = attrs[:size] || 0
        @mode = attrs[:mode] || :personal
        @status = attrs[:status] || UNMOUNTED
        @mount_point = attrs[:mount_point]
        @created_at = attrs[:created_at]
      end

      def mounted?
        @status == MOUNTED
      end

      def mode_name
        MODES.dig(@mode, :name) || "Unknown"
      end

      def size_human
        return "0 B" unless @size && @size > 0
        units = %w[B KB MB GB TB]
        val = @size.to_f
        units.each do |u|
          return format("%.1f %s", val, u) if val < 1024
          val /= 1024
        end
        format("%.1f PB", val)
      end
    end

    # Volume manager — handles all volume operations.
    class Manager
      attr_reader :volumes

      def initialize
        @volumes = []
        @mutex = Mutex.new
      end

      # Create a new encrypted volume.
      def create(name:, path:, size:, passphrase:, mode: :personal)
        mode_cfg = MODES[mode] || MODES[:personal]
        volume_path = File.join(path, "#{name}.sot")

        result = Soteria::CoreBridge.encrypt(
          src: "/dev/zero",
          into: path,
          name: name,
          passphrase: passphrase,
          fast_kdf: false
        )

        vol = VolumeInfo.new(
          name: name,
          path: volume_path,
          size: size,
          mode: mode,
          status: UNMOUNTED,
          created_at: Time.now
        )

        @mutex.synchronize { @volumes << vol }
        vol
      end

      # Mount a volume.
      def mount(volume, passphrase:, mount_point: nil)
        mount_point ||= default_mount_point(volume.name)

        # Use the Rust CLI to mount
        result = Soteria::CoreBridge.run(
          "quick-mount",
          "--volume", File.dirname(volume.path),
          "--name", File.basename(volume.path, ".sot"),
          "--passphrase", passphrase,
          "--mountpoint", mount_point
        )

        vol = find_volume(volume.name)
        if vol
          vol.instance_variable_set(:@status, MOUNTED)
          vol.instance_variable_set(:@mount_point, mount_point)
        end
        result
      end

      # Unmount a volume.
      def unmount(volume, passphrase:)
        result = Soteria::CoreBridge.run(
          "unmount",
          "--mountpoint", volume.mount_point,
          "--volume", File.dirname(volume.path),
          "--name", File.basename(volume.path, ".sot"),
          "--passphrase", passphrase
        )

        vol = find_volume(volume.name)
        if vol
          vol.instance_variable_set(:@status, UNMOUNTED)
          vol.instance_variable_set(:@mount_point, nil)
        end
        result
      end

      # Verify volume integrity.
      def verify(volume)
        Soteria::CoreBridge.verify(dir: File.dirname(volume.path))
      end

      # List all volumes in a directory.
      def scan(dir)
        result = Soteria::CoreBridge.list(dir: dir)
        volumes = []
        if result["files"]
          result["files"].each do |f|
            volumes << VolumeInfo.new(
              name: f["name"],
              path: File.join(dir, f["name"]),
              size: f["size"],
              status: UNMOUNTED
            )
          end
        end
        @mutex.synchronize { @volumes = volumes }
        volumes
      end

      def find_volume(name)
        @mutex.synchronize { @volumes.find { |v| v.name == name } }
      end

      def mounted_volumes
        @mutex.synchronize { @volumes.select(&:mounted?) }
      end

      def unmounted_volumes
        @mutex.synchronize { @volumes.reject(&:mounted?) }
      end

      private

      def default_mount_point(name)
        if Gem.win_platform?
          # Find first available drive letter
          ("D".."Z").each do |letter|
            path = "#{letter}:\\"
            return path unless Dir.exist?(path)
          end
          "Z:\\"
        else
          base = File.join(Dir.home, ".soteria", "mount")
          FileUtils.mkdir_p(base)
          File.join(base, name)
        end
      end
    end
  end
end
