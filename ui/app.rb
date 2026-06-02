# frozen_string_literal: true

require "sinatra"
require "sinatra/json"
require "erubi"
require_relative "lib/api_client"

# Soteria Web UI — Sinatra application.
# Communicates with the Rust backend (`soteriad serve`) via REST API.
class SoteriaUI < Sinatra::Base
  set :root, File.dirname(__FILE__)
  set :views, File.join(settings.root, "views")
  set :public_folder, File.join(settings.root, "public")
  set :erb, engine: :erubi, engine_class: Erubi::CaptureBlockEngine
  set :show_exceptions, false
  set :raise_errors, false

  # ── Helpers ───────────────────────────────────────────────────────
  helpers do
    def api
      SoteriaAPI.client
    end

    def h(text)
      Rack::Utils.escape_html(text.to_s)
    end

    def json_response(data, status = 200)
      content_type :json
      status status
      JSON.generate(data)
    end

    def json_error(message, status = 500)
      json_response({ error: message }, status)
    end

    def protection_color(score)
      return "green" if score >= 80
      return "amber" if score >= 50
      "red"
    end

    def severity_icon(severity)
      case severity.to_s.downcase
      when "critical", "high" then "alert-triangle"
      when "warning", "medium" then "alert-circle"
      when "info", "low" then "info"
      else "check-circle"
      end
    end

    def relative_time(timestamp)
      return "just now" unless timestamp
      diff = Time.now.to_i - timestamp.to_i
      return "#{diff}s ago" if diff < 60
      return "#{diff / 60}m ago" if diff < 3600
      return "#{diff / 3600}h ago" if diff < 86400
      "#{diff / 86400}d ago"
    end

    def format_bytes(bytes)
      return "0 B" if bytes.nil? || bytes.zero?
      units = %w[B KB MB GB TB PB]
      exp = (Math.log(bytes) / Math.log(1024)).to_i
      exp = units.length - 1 if exp >= units.length
      "%.1f %s" % [bytes.to_f / (1024 ** exp), units[exp]]
    end
  end

  # ── Error handling ────────────────────────────────────────────────
  error SoteriaAPI::Client::ApiError do
    err = env["sinatra.error"]
    if request.content_type&.include?("application/json")
      json_error(err.message)
    else
      @error = err.message
      erb :"dashboard/index"
    end
  end

  error do
    err = env["sinatra.error"]
    if request.content_type&.include?("application/json")
      json_error(err.message)
    else
      @error = "An unexpected error occurred: #{err.message}"
      erb :"dashboard/index"
    end
  end

  # ── Dashboard ─────────────────────────────────────────────────────
  get "/" do
    @protection = begin
      api.protection_score
    rescue SoteriaAPI::Client::ApiError
      { "status" => "offline", "score" => 0, "message" => "Soteria daemon is not running" }
    end
    @storage = begin
      api.storage_overview
    rescue SoteriaAPI::Client::ApiError
      { "total_bytes" => 0, "encrypted_bytes" => 0, "domain_count" => 0 }
    end
    @events = begin
      api.events(limit: 5)
    rescue SoteriaAPI::Client::ApiError
      { "events" => [] }
    end
    @recovery = begin
      api.recovery_status
    rescue SoteriaAPI::Client::ApiError
      { "verified" => false, "last_tested" => nil }
    end
    @devices = begin
      api.devices
    rescue SoteriaAPI::Client::ApiError
      { "devices" => [] }
    end
    @keys = begin
      api.key_lifecycle
    rescue SoteriaAPI::Client::ApiError
      { "rotation_health" => "unknown", "next_rotation" => nil }
    end
    erb :"dashboard/index"
  end

  # ── Protection ────────────────────────────────────────────────────
  get "/protection" do
    @protection = api.protection_score
    @integrity = api.integrity_check
    erb :"dashboard/protection"
  end

  post "/protection/integrity-check" do
    result = api.integrity_check
    json_response(result)
  end

  # ── Storage ───────────────────────────────────────────────────────
  get "/storage" do
    @storage = api.storage_overview
    @domains = api.domains
    erb :"domains/index"
  end

  post "/storage/encrypt" do
    result = api.encrypt(
      src: params[:src],
      into: params[:into],
      name: params[:name],
      passphrase: params[:passphrase],
      fast_kdf: params[:fast_kdf] == "true"
    )
    json_response(result)
  end

  post "/storage/decrypt" do
    result = api.decrypt(
      from: params[:from],
      name: params[:name],
      passphrase: params[:passphrase],
      output: params[:output]
    )
    json_response(result)
  end

  post "/storage/verify" do
    result = api.verify_volumes(params[:dir])
    json_response(result)
  end

  # ── Domains ───────────────────────────────────────────────────────
  get "/domains" do
    @domains = api.domains
    erb :"domains/index"
  end

  get "/domains/:id" do
    @domain = api.domain_detail(params[:id])
    erb :"domains/show"
  end

  post "/domains" do
    result = api.create_domain(
      name: params[:name],
      path: params[:path],
      algorithm: params[:algorithm]
    )
    json_response(result)
  end

  # ── Devices ───────────────────────────────────────────────────────
  get "/devices" do
    @devices = api.devices
    erb :"dashboard/devices"
  end

  get "/devices/:id" do
    @device = api.device_detail(params[:id])
    erb :"dashboard/device_detail"
  end

  # ── Events / Threats ──────────────────────────────────────────────
  get "/threats" do
    @events = api.events(limit: 50, severity: params[:severity], category: params[:category])
    @threat_summary = begin
      api.threat_summary
    rescue SoteriaAPI::Client::ApiError
      {}
    end
    @canary = begin
      api.canary_status
    rescue SoteriaAPI::Client::ApiError
      { "active" => false, "hits" => 0 }
    end
    @honey = begin
      api.honey_status
    rescue SoteriaAPI::Client::ApiError
      { "active" => false, "interactions" => 0 }
    end
    erb :"threats/index"
  end

  get "/threats/events" do
    @events = api.events(limit: 100, severity: params[:severity], category: params[:category])
    erb :"threats/events"
  end

  get "/threats/events/:id" do
    @event = api.event_detail(params[:id])
    erb :"threats/event_detail"
  end

  post "/threats/simulate" do
    result = api.simulate_event(
      event_type: params[:event_type],
      severity: params[:severity].to_i
    )
    json_response(result)
  end

  get "/threats/deception" do
    @canary = api.canary_status
    @honey = api.honey_status
    erb :"threats/deception"
  end

  get "/threats/anomalies" do
    @anomalies = api.anomaly_status
    erb :"threats/anomalies"
  end

  # ── Keys ──────────────────────────────────────────────────────────
  get "/keys" do
    @keys = api.key_lifecycle
    erb :"keys/index"
  end

  post "/keys/keygen" do
    result = api.keygen(
      scheme: params[:scheme] || "ml-kem-768",
      out: params[:out]
    )
    json_response(result)
  end

  post "/keys/rotate" do
    result = api.rotate_keys(domain: params[:domain])
    json_response(result)
  end

  # ── Sharing ───────────────────────────────────────────────────────
  get "/share" do
    if params[:volume] && params[:passphrase]
      @share_list = api.share_list(volume: params[:volume], passphrase: params[:passphrase])
    end
    erb :"keys/share"
  end

  post "/share/add" do
    result = api.share_add(
      volume: params[:volume],
      passphrase: params[:passphrase],
      recipient_pk: params[:recipient_pk],
      owner_sk: params[:owner_sk]
    )
    json_response(result)
  end

  post "/share/remove" do
    result = api.share_remove(
      volume: params[:volume],
      passphrase: params[:passphrase],
      recipient_pk: params[:recipient_pk],
      reason: params[:reason]
    )
    json_response(result)
  end

  post "/share/unlock" do
    result = api.share_unlock(
      volume: params[:volume],
      sk: params[:sk],
      out: params[:out],
      owner_pk: params[:owner_pk],
      no_verify_signature: params[:no_verify_signature] == "true"
    )
    json_response(result)
  end

  # ── Recovery ──────────────────────────────────────────────────────
  get "/recovery" do
    @recovery = api.recovery_status
    erb :"recovery/index"
  end

  post "/recovery/verify" do
    result = api.recovery_verify(
      key: params[:key],
      volume: params[:volume]
    )
    json_response(result)
  end

  post "/recovery/create" do
    result = api.recovery_create(
      method: params[:method],
      output: params[:output]
    )
    json_response(result)
  end

  # ── Audit ─────────────────────────────────────────────────────────
  get "/audit" do
    if params[:log]
      @audit = api.audit_log(params[:log])
    end
    erb :"threats/audit"
  end

  post "/audit/verify" do
    result = api.audit_verify(params[:log])
    json_response(result)
  end

  # ── Settings ──────────────────────────────────────────────────────
  get "/settings" do
    @settings = api.settings
    erb :"settings/index"
  end

  put "/settings" do
    result = api.update_settings(params)
    json_response(result)
  end

  # ── Installer ─────────────────────────────────────────────────────
  get "/installer" do
    erb :"installer/welcome"
  end

  get "/installer/scan" do
    @system_check = api.system_check
    erb :"installer/scan"
  end

  get "/installer/mode" do
    erb :"installer/mode"
  end

  get "/installer/recovery" do
    erb :"installer/recovery"
  end

  get "/installer/preview" do
    erb :"installer/preview"
  end

  get "/installer/deploy" do
    erb :"installer/deploy"
  end

  post "/installer/deploy" do
    result = api.installer_deploy(
      mode: params[:mode],
      passphrase: params[:passphrase],
      recovery_method: params[:recovery_method],
      recovery_output: params[:recovery_output]
    )
    json_response(result)
  end

  get "/installer/done" do
    @status = api.installer_status
    erb :"installer/done"
  end

  # ── Learning Center ───────────────────────────────────────────────
  get "/learn" do
    erb :"learning/index"
  end

  get "/learn/:topic" do
    @topic = params[:topic]
    erb :"learning/topic"
  end

  # ── API proxy endpoints (for Turbo/Stimulus) ──────────────────────
  get "/api/proxy/*" do
    path = "/api/#{params[:splat].first}"
    result = api.send(:get, path, params.reject { |k, _| %w[splat captures].include?(k.to_s) })
    json_response(result)
  end

  post "/api/proxy/*" do
    path = "/api/#{params[:splat].first}"
    body = JSON.parse(request.body.read) rescue {}
    result = api.send(:post, path, body)
    json_response(result)
  end
end
