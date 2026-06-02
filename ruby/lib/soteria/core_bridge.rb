# frozen_string_literal: true

require "json"
require "open3"

module Soteria
  # Bridge between Ruby tooling and the Rust soteriad binary.
  # All cryptographic operations go through this bridge — Ruby never
  # touches keys or ciphertext directly.
  module CoreBridge
    module_function

    # Run a soteriad command and return parsed JSON output.
    def run(*args, stdin: nil)
      cmd = [Soteria.binary_path] + args
      stdout, stderr, status = Open3.capture3(*cmd, stdin_data: stdin)

      unless status.success?
        raise Soteria::Error, "soteriad #{args.first} failed (exit #{status.exitstatus}): #{stderr.strip}"
      end

      # Try to parse JSON, fall back to raw stdout.
      JSON.parse(stdout)
    rescue JSON::ParserError
      { "raw" => stdout.strip }
    end

    # Encrypt a file.
    def encrypt(src:, into:, name:, passphrase:, fast_kdf: false)
      args = ["encrypt", "--src", src, "--into", into, "--name", name, "--passphrase", passphrase]
      args << "--fast-kdf" if fast_kdf
      run(*args)
    end

    # Decrypt a file.
    def decrypt(from:, name:, passphrase: nil, key_file: nil, output:)
      args = ["decrypt", "--from", from, "--name", name, "--output", output]
      if passphrase
        args += ["--passphrase", passphrase]
      elsif key_file
        args += ["--key-file", key_file]
      end
      run(*args)
    end

    # Generate a keypair.
    def keygen(out:, scheme: "ml-kem-768")
      run("keygen", "--scheme", scheme, "--out", out)
    end

    # Add a recipient to a volume.
    def share_add(volume:, passphrase:, recipient_pk:, owner_sk:)
      run("share", "add",
          "--volume", volume,
          "--passphrase", passphrase,
          "--recipient-pk", recipient_pk,
          "--owner-sk", owner_sk)
    end

    # Remove a recipient.
    def share_remove(volume:, passphrase:, recipient_pk:, reason: "manual revocation")
      run("share", "remove",
          "--volume", volume,
          "--passphrase", passphrase,
          "--recipient-pk", recipient_pk,
          "--reason", reason)
    end

    # List recipients.
    def share_list(volume:, passphrase:)
      run("share", "list", "--volume", volume, "--passphrase", passphrase)
    end

    # Unlock a share.
    def share_unlock(volume:, sk:, out:, owner_pk: nil, no_verify_signature: false)
      args = ["share", "unlock", "--volume", volume, "--sk", sk, "--out", out]
      args += ["--owner-pk", owner_pk] if owner_pk
      args << "--no-verify-signature" if no_verify_signature
      run(*args)
    end

    # Verify volumes.
    def verify(dir:)
      run("verify", "--dir", dir)
    end

    # List volumes.
    def list(dir:)
      run("list", "--dir", dir)
    end

    # Inspect audit log.
    def audit(log:, verify_only: false)
      args = ["audit", "--log", log]
      args << "--verify-only" if verify_only
      run(*args)
    end
  end
end
