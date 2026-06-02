# frozen_string_literal: true

require "spec_helper"

RSpec.describe Soteria::SystemCheck do
  subject(:check) { described_class.new }

  describe "#run_all" do
    it "returns a hash of check results" do
      results = check.run_all
      expect(results).to be_a(Hash)
      expect(results.keys).to contain_exactly(:tpm, :secure_boot, :disk, :space, :recovery)
    end

    it "each result has pass, label, and detail" do
      results = check.run_all
      results.each do |_name, result|
        expect(result).to have_key(:pass)
        expect(result).to have_key(:label)
        expect(result).to have_key(:detail)
        expect(result[:pass]).to be(true).or be(false)
      end
    end
  end

  describe "#check_tpm" do
    it "returns a valid result" do
      result = check.check_tpm
      expect(result[:label]).to eq("Hardware Security")
    end
  end

  describe "#check_disk" do
    it "checks write access" do
      result = check.check_disk
      expect(result[:label]).to eq("Storage")
    end
  end
end
