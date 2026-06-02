# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

# Client for the Soteria REST API exposed by `soteriad serve`.
# All methods return parsed JSON hashes. Raises on HTTP errors.
module SoteriaAPI
  class Client
    class ApiError < StandardError; end

    def initialize(base_url = "http://127.0.0.1:7777")
      @base_url = base_url
    end

    # ── Status ──────────────────────────────────────────────────────
    def status
      get("/api/status")
    end

    # ── Protection ──────────────────────────────────────────────────
    def protection_score
      get("/api/protection/score")
    end

    def integrity_check
      post("/api/protection/integrity-check")
    end

    # ── Storage ─────────────────────────────────────────────────────
    def storage_overview
      get("/api/storage")
    end

    def list_volumes(dir)
      get("/api/storage/volumes", dir: dir)
    end

    def encrypt(params)
      post("/api/storage/encrypt", params)
    end

    def decrypt(params)
      post("/api/storage/decrypt", params)
    end

    def verify_volumes(dir)
      post("/api/storage/verify", dir: dir)
    end

    # ── Domains ─────────────────────────────────────────────────────
    def domains
      get("/api/domains")
    end

    def create_domain(params)
      post("/api/domains", params)
    end

    def domain_detail(id)
      get("/api/domains/#{id}")
    end

    # ── Keys ────────────────────────────────────────────────────────
    def key_lifecycle
      get("/api/keys")
    end

    def keygen(scheme: "ml-kem-768", out:)
      post("/api/keys/keygen", scheme: scheme, out: out)
    end

    def rotate_keys(domain: nil)
      post("/api/keys/rotate", domain: domain)
    end

    # ── Sharing ─────────────────────────────────────────────────────
    def share_add(params)
      post("/api/share/add", params)
    end

    def share_remove(params)
      post("/api/share/remove", params)
    end

    def share_list(volume:, passphrase:)
      get("/api/share/list", volume: volume, passphrase: passphrase)
    end

    def share_unlock(params)
      post("/api/share/unlock", params)
    end

    # ── Events / Threats ────────────────────────────────────────────
    def events(limit: 50, severity: nil, category: nil)
      params = { limit: limit }
      params[:severity] = severity if severity
      params[:category] = category if category
      get("/api/events", params)
    end

    def event_detail(id)
      get("/api/events/#{id}")
    end

    def simulate_event(params)
      post("/api/events/simulate", params)
    end

    # ── Threats ─────────────────────────────────────────────────────
    def threat_summary
      get("/api/threats/summary")
    end

    def canary_status
      get("/api/threats/canaries")
    end

    def honey_status
      get("/api/threats/honey")
    end

    def anomaly_status
      get("/api/threats/anomalies")
    end

    # ── Recovery ────────────────────────────────────────────────────
    def recovery_status
      get("/api/recovery")
    end

    def recovery_verify(params)
      post("/api/recovery/verify", params)
    end

    def recovery_create(params)
      post("/api/recovery/create", params)
    end

    # ── Audit ───────────────────────────────────────────────────────
    def audit_log(path)
      get("/api/audit", log: path)
    end

    def audit_verify(path)
      post("/api/audit/verify", log: path)
    end

    # ── Devices ─────────────────────────────────────────────────────
    def devices
      get("/api/devices")
    end

    def device_detail(id)
      get("/api/devices/#{id}")
    end

    # ── Settings ────────────────────────────────────────────────────
    def settings
      get("/api/settings")
    end

    def update_settings(params)
      put("/api/settings", params)
    end

    # ── Installer ───────────────────────────────────────────────────
    def system_check
      post("/api/installer/system-check")
    end

    def installer_deploy(params)
      post("/api/installer/deploy", params)
    end

    def installer_status
      get("/api/installer/status")
    end

    private

    def get(path, params = {})
      uri = URI("#{@base_url}#{path}")
      uri.query = URI.encode_www_form(params) unless params.empty?
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"
      execute(request)
    end

    def post(path, body = {})
      uri = URI("#{@base_url}#{path}")
      request = Net::HTTP::Post.new(uri)
      request["Content-Type"] = "application/json"
      request["Accept"] = "application/json"
      request.body = JSON.generate(body)
      execute(request)
    end

    def put(path, body = {})
      uri = URI("#{@base_url}#{path}")
      request = Net::HTTP::Put.new(uri)
      request["Content-Type"] = "application/json"
      request["Accept"] = "application/json"
      request.body = JSON.generate(body)
      execute(request)
    end

    def execute(request)
      response = Net::HTTP.start(
        request.uri.hostname,
        request.uri.port,
        open_timeout: 5,
        read_timeout: 30
      ) { |http| http.request(request) }

      unless response.is_a?(Net::HTTPSuccess)
        error_body = begin
          JSON.parse(response.body)
        rescue StandardError
          { "error" => response.body }
        end
        raise ApiError, error_body["error"] || "HTTP #{response.code}"
      end

      JSON.parse(response.body)
    rescue Errno::ECONNREFUSED
      raise ApiError, "Soteria daemon is not running. Start it with: soteriad serve"
    rescue JSON::ParserError
      raise ApiError, "Invalid JSON response from Soteria daemon"
    end
  end

  # Singleton client instance for the app.
  def self.client
    @client ||= Client.new(ENV.fetch("SOTERIA_API_URL", "http://127.0.0.1:7777"))
  end
end
