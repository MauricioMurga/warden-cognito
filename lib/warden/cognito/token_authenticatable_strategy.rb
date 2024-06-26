require 'aws-sdk-cognitoidentityprovider'
# rubocop:disable Style/SignalException

module Warden
  module Cognito
    class TokenAuthenticatableStrategy < Warden::Strategies::Base
      METHOD = 'Bearer'.freeze

      attr_reader :helper

      def initialize(env, scope = nil)
        super
        @helper = UserHelper.new
      end

      def valid?
        if ENV['RAILS_ENV'].to_s == 'test'
          true
        else
          token_decoder.validate!
        end
      rescue ::JWT::ExpiredSignature
        true
      rescue StandardError
        false
      end

      def authenticate!
        user = local_user || UserNotFoundCallback.call(cognito_user, token_decoder.pool_identifier)

        fail!(:unknown_user) unless user.present?
        success!(user)
      rescue ::JWT::ExpiredSignature
        fail!(:token_expired)
      rescue JWT::InvalidIssuerError
        fail(:invalid)
      rescue StandardError
        fail(:unknown_error)
      end

      private

      def cognito_user
        token_decoder.cognito_user
      end

      def local_user
        LocalUserMapper.find token_decoder
      end

      def token_decoder
        @token_decoder ||= TokenDecoder.new(token, pool_identifier)
      end

      def pool_identifier
        env['HTTP_X_AUTHORIZATION_POOL_IDENTIFIER']
      end

      def token
        @token ||= extract_token
      end

      def extract_token
        return nil unless authorization_header

        method, token = authorization_header.split
        method == METHOD ? token : nil
      end

      def authorization_header
        env['HTTP_AUTHORIZATION']
      end
    end
  end
end
# rubocop:enable Style/SignalException

Warden::Strategies.add(:cognito_jwt, Warden::Cognito::TokenAuthenticatableStrategy)
