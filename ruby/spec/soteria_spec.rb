# frozen_string_literal: true

require "spec_helper"

RSpec.describe Soteria do
  it "has a version number" do
    expect(Soteria::VERSION).to eq("0.1.0")
  end

  it "defines a binary path" do
    expect(Soteria.binary_path).to be_a(String)
    expect(Soteria.binary_path).to include("soteriad")
  end
end
