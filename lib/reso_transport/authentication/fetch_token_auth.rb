module ResoTransport
  module Authentication
    class FetchTokenAuth < AuthStrategy
      attr_reader :endpoint, :client_id, :client_secret, :grant_type, :scope, :username, :password

      def initialize(options)
        super()

        @grant_type    = options.fetch(:grant_type, 'client_credentials')
        @scope         = options.fetch(:scope, 'api')
        @client_id     = options.fetch(:client_id)
        @client_secret = options.fetch(:client_secret)
        @endpoint      = options.fetch(:endpoint)
        @username      = options.fetch(:username, nil)
        @password      = options.fetch(:password, nil)
        @request       = nil
      end

      def connection
        @connection ||= Faraday.new(@endpoint) do |faraday|
          faraday.request :url_encoded
          faraday.request :authorization, :basic, client_id, client_secret
          faraday.response :logger, ResoTransport.configuration.logger if ResoTransport.configuration.logger
          faraday.adapter Faraday.default_adapter
        end
      end

      def authenticate
        response = connection.post(nil, auth_params { |req| @request = req })
        json = parse_token_response(response.body)

        # Some token servers (e.g. AWS Cognito behind a proxy) report failures
        # with HTTP 200 and an OAuth error body, so check the body too.
        if !response.success? || json['error'] || !json['access_token']
          raise AccessDenied.new(request, response, 'token', reason: token_error_reason(response, json))
        end

        Access.new({
          access_token: json.fetch('access_token'),
          expires_in: json.fetch('expires_in', 1 << (1.size * 8 - 2) - 1),
          token_type: json.fetch('token_type', 'Bearer')
        })
      end

      def request
        return @request.to_h if @request.respond_to? :to_h

        {}
      end

      private

      def parse_token_response(body)
        json = JSON.parse(body.to_s)
        json.is_a?(Hash) ? json : {}
      rescue JSON::ParserError
        {}
      end

      # Prefer the OAuth error fields (RFC 6749 section 5.2) over the HTTP reason phrase
      def token_error_reason(response, json)
        reason = [json['error'], json['error_description']].compact.map(&:to_s).reject(&:empty?).join(': ')
        reason = "no access_token in token response (HTTP #{response.status})" if reason.empty? && response.success?
        reason.empty? ? response.reason_phrase : reason
      end

      def auth_params
        params = {
          client_id: client_id,
          client_secret: client_secret,
          grant_type: grant_type,
          scope: scope
        }

        if grant_type == 'password'
          params[:username] = username
          params[:password] = password
        end

        params
      end
    end
  end
end
