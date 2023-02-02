module Warden
  module Cognito
    class CognitoClient
      include Cognito::Import['user_pools']
      include HasUserPoolIdentifier

      # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CognitoIdentityProvider/Types/GetUserResponse.html
      def fetch(access_token)
        client.get_user(access_token: access_token)
      end

      def initiate_auth(username, password)
        client.initiate_auth(
          client_id: user_pool.client_id,
          auth_flow: 'USER_PASSWORD_AUTH',
          auth_parameters: {
            USERNAME: username,
            PASSWORD: password
          }.merge(secret_hash(username))
        )
      end

      def sign_up(username, password)
        client.sign_up(
          client_id: user_pool.client_id,
          username: username,
          password: password,
          secret_hash: secret_hash(username)[:SECRET_HASH]
        )
      end

      def refresh_token(username, refresh_token)
        client.initiate_auth(
          client_id: user_pool.client_id,
          auth_flow: 'REFRESH_TOKEN_AUTH',
          auth_parameters: {
            REFRESH_TOKEN: refresh_token
          }.merge(secret_hash(username))
        )
      end

      def revoke_token(refresh_token)
        client.revoke_token(
          token: refresh_token,
          client_id: user_pool.client_id,
          client_secret: user_pool.secret
        )
      end

      def update_email(email, access_token)
        client.update_user_attributes(
          access_token: access_token,
          user_attributes: [
            {
              name: "email",
              value: email
            }
        ])
      end

      def change_password(passwords, access_token)
        client.change_password(
          previous_password: passwords[:current_password],
          proposed_password: passwords[:password],
          access_token: access_token
        )
      end

      def verify_email(code, access_token)
        client.verify_user_attribute(
          access_token: access_token,
          attribute_name: "email",
          code: code.to_s
        )
      end

      # Sends verification code for current email
      def send_email_verification_code(access_token)
        client.get_user_attribute_verification_code(
          access_token: access_token,
          attribute_name: "email"
        )
      end

      def fogot_password(username)
        client.forgot_password(
          client_id: user_pool.client_id,
          secret_hash: secret(username),
          username: username
        )
      end

      def confirm_password(username, password, code)
        client.confirm_forgot_password({
          client_id: user_pool.client_id,
          secret_hash: secret(username),
          username: username,
          confirmation_code: code,
          password: password
        })
      end

      private

      def client
        Aws::CognitoIdentityProvider::Client.new(client_attributes)
      end

      def client_attributes
        attributes = {
          region: user_pool.region,
          stub_responses: testing?,
          validate_params: !testing?
        }
        if ENV['COGNITO_ACCESS_KEY_ID'] && ENV['COGNITO_SECRET_ACCESS_KEY']
          attributes.merge!(
            access_key_id: ENV['COGNITO_ACCESS_KEY_ID'],
            secret_access_key: ENV['COGNITO_SECRET_ACCESS_KEY']
          )
        end
        attributes
      end

      def testing?
        environment.blank? || environment == 'test'
      end

      def environment
        ENV['RAILS_ENV'].to_s
      end

      def secret_hash(email)
        return {} if user_pool.secret.blank?
        {
          SECRET_HASH: secret(email)
        }
      end

      def secret(username)
        key = user_pool.secret
        data = username + user_pool.client_id
        Base64.strict_encode64(OpenSSL::HMAC.digest('sha256', key, data))
      end

      class << self
        def scope(pool_identifier)
          new.tap do |client|
            client.user_pool = pool_identifier || default_pool_identifier
          end
        end

        private

        def default_pool_identifier
          Warden::Cognito.config.user_pools.first.identifier
        end
      end
    end
  end
end
