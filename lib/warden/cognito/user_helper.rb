module Warden
  module Cognito
    class UserHelper
      include Cognito::Import['user_repository']

      def find_by_cognito_username(username, pool_identifier, tokens = {})
        user_repository.find_by_cognito_username(username, pool_identifier, tokens)
      end

      def find_by_cognito_attribute(arg, pool_identifier, access_token, expires_at)
        user_repository.find_by_cognito_attribute(arg, pool_identifier, access_token, expires_at)
      end
    end
  end
end
