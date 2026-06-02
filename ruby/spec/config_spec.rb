# frozen_string_literal: true

require "spec_helper"

RSpec.describe Soteria::Config do
  subject(:config) { described_class.new }

  it "loads default values" do
    expect(config["crypto"]).to be_a(Hash)
    expect(config.dig("crypto", "algorithm")).to eq("xchacha20-poly1305")
    expect(config.dig("crypto", "block_size")).to eq(65536)
  end

  it "provides key lifecycle defaults" do
    expect(config.dig("key_lifecycle", "enforce_zeroize")).to be true
  end

  it "provides fuse defaults" do
    expect(config.dig("fuse", "flush_interval_secs")).to eq(30)
    expect(config.dig("fuse", "read_cache_mb")).to eq(64)
  end
end
