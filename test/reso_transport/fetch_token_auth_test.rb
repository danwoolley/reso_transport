# Standalone unit test (no live MLS credentials needed):
#   ruby -Ilib test/reso_transport/fetch_token_auth_test.rb
require 'minitest/autorun'
require 'reso_transport'

class FetchTokenAuthTest < Minitest::Test
  TOKEN_URL = 'https://auth.example.com/oauth2/token'.freeze

  def auth_with(status, body, reason_phrase = nil)
    auth = ResoTransport::Authentication::FetchTokenAuth.new(
      endpoint: TOKEN_URL, client_id: 'id', client_secret: 'secret'
    )
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post(TOKEN_URL) { [status, { 'Content-Type' => 'application/json' }, body] }
    end
    auth.instance_variable_set(:@connection, Faraday.new(TOKEN_URL) do |f|
      f.request :url_encoded
      f.adapter :test, stubs
    end)
    auth
  end

  def test_successful_token
    access = auth_with(200, '{"access_token":"abc","expires_in":3600,"token_type":"Bearer"}').authenticate
    assert_equal 'abc', access.access_token
    assert_equal 'Bearer', access.token_type
  end

  def test_oauth_error_with_http_200_raises_access_denied
    err = assert_raises(ResoTransport::AccessDenied) { auth_with(200, '{"error":"invalid_scope"}').authenticate }
    assert_equal 'Access denied: invalid_scope', err.message
  end

  def test_oauth_error_with_http_400_includes_description
    body = '{"error":"invalid_client","error_description":"Client authentication failed"}'
    err = assert_raises(ResoTransport::AccessDenied) { auth_with(400, body).authenticate }
    assert_equal 'Access denied: invalid_client: Client authentication failed', err.message
  end

  def test_http_200_without_access_token_raises_access_denied
    err = assert_raises(ResoTransport::AccessDenied) { auth_with(200, '{"foo":"bar"}').authenticate }
    assert_match(/no access_token/, err.message)
  end

  def test_non_json_error_body_raises_access_denied_not_parser_error
    assert_raises(ResoTransport::AccessDenied) { auth_with(502, '<html>Bad Gateway</html>').authenticate }
  end
end
