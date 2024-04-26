require 'aws-sdk-cognitoidentityprovider'
# rubocop:disable Style/SignalException

module Warden
  module Cognito
    class AuthenticatableStrategy < Warden::Strategies::Base
      attr_reader :helper, :user_not_found_callback

      def initialize(env, scope = nil)
        super
        @user_not_found_callback = UserNotFoundCallback.new
        @helper = UserHelper.new
      end

      def valid?
        allow_auth_in_root
        cognito_authenticable?
      end

      def authenticate!
        attempt = cognito_client.initiate_auth(email, password)

        return fail(:unknow_cognito_response) unless attempt

        user = local_user(attempt.authentication_result) ||
               trigger_callback(attempt.authentication_result)

        if user.present?
          success!(user)
        else
          fail!(:invalid)
        end
      rescue Aws::CognitoIdentityProvider::Errors::NotAuthorizedException
        fail!(:invalid)
      rescue Aws::CognitoIdentityProvider::Errors::UserNotConfirmedException
        fail!(:unconfirmed)
      rescue StandardError
        fail(:unknow_cognito_response)
      end

      private

      def cognito_client
        CognitoClient.scope pool_identifier
      end

      def trigger_callback(auth_result)
        cognito_user = cognito_client.fetch(auth_result.access_token)
        user_not_found_callback.call(cognito_user, cognito_client.pool_identifier)
      end

      def local_user(auth_result)
        tokens = {
          access_token: auth_result.access_token,
          refresh_token: auth_result.refresh_token,
          expires_at: auth_result.expires_in.to_i + Time.now.to_i
        }
        helper.find_by_cognito_username(email, cognito_client.pool_identifier, tokens)
      end

      def cognito_authenticable?
        params[scope.to_s].present? && password.present?
      end

      def email
        auth_params[:email]
      end

      def password
        auth_params[:password]
      end

      def pool_identifier
        auth_params[:pool_identifier]&.to_sym
      end

      def auth_params
        params[scope.to_s].symbolize_keys.slice(:password, :email, :pool_identifier)
      end

      # Allow auth params in root
      def allow_auth_in_root
        return unless params[:session] && params[scope.to_s].blank?

        params[scope.to_s] = params[:session]
      end
    end
  end
end
# rubocop:enable Style/SignalException

Warden::Strategies.add(:cognito_auth, Warden::Cognito::AuthenticatableStrategy)
