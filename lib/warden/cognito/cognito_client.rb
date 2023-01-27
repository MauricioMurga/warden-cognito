module Warden
  module Cognito
    class CognitoClient
      include Cognito::Import['user_pools']
      include HasUserPoolIdentifier

      # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CognitoIdentityProvider/Types/GetUserResponse.html
      def fetch(access_token)
        client.get_user(access_token: access_token)
      end

      def initiate_auth(email, password)
        client.initiate_auth(
          client_id: user_pool.client_id,
          auth_flow: 'USER_PASSWORD_AUTH',
          auth_parameters: {
            USERNAME: email,
            PASSWORD: password
          }.merge(secret_hash(email))
        )
      end

      def sign_up(email, password)
        client.sign_up(
          client_id: user_pool.client_id,
          username: email,
          password: password,
          secret_hash: secret_hash(email)[:SECRET_HASH]
        )
      end

      private

      def client
        Aws::CognitoIdentityProvider::Client.new(client_attributes)
      end

      def client_attributes
        {
          region: user_pool.region,
          stub_responses: testing?,
          validate_params: !testing?
        }
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
