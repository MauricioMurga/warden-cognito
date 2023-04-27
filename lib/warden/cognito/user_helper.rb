module Warden
  module Cognito
    class UserHelper
      include Cognito::Import['user_repository']

      def find_by_cognito_username(username, pool_identifier, tokens = {})
        user_repository.find_by_cognito_username(username, pool_identifier, tokens)
      end

      def find_by_cognito_attribute(arg, pool_identifier, access_token)
        user_repository.find_by_cognito_attribute(arg, pool_identifier, access_token)
      end
    end
  end
end
