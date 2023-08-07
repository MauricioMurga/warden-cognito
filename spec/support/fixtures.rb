# frozen_string_literal: true

require 'singleton'

module Fixtures
  # An user record
  class User
    include Singleton
    attr_accessor :access_token, :refresh_token, :expires_at

    def cognito_id
      object_id
    end
  end

  # User repository
  class UserRepo
    def self.find_by_cognito_username(_username, _pool_identifier, tokens)
      u = User.instance
      u.access_token = tokens[:access_token]
      u.refresh_token = tokens[:refresh_token]
      u.expires_at = tokens[:expires_at]
      u
    end

    def self.find_by_cognito_attribute(_attribute, _pool_identifier, _access_token, _expires_at)
      User.instance
    end
  end

  # User repository that mimics returning a nil user (probably a user that has
  # been deleted)
  class NilUserRepo
    def self.find_by_cognito_username(_username, _pool_identifier, _access_token)
      nil
    end

    def self.find_by_cognito_attribute(_attribute, _pool_identifier, _access_token, _expires_at)
      nil
    end
  end

  # Callbacks to call whenever an authenticated user is not present locally
  class Callback
    # Returning nil meaning we could not import the user
    def self.after_user_local_not_found_nil
      proc do |_arg|
        nil
      end
    end

    # Returning nil meaning the user eventually got created locally or is referencing a one-time external resource
    def self.after_user_local_not_found_user
      proc do |_arg|
        User.instance
      end
    end
  end
end
