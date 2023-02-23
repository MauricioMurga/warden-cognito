require 'spec_helper'
require 'rack'

RSpec.describe Warden::Cognito::AuthenticatableStrategy do
  include_context 'fixtures'
  include_context 'configuration'

  let(:scope) { :v2_user }
  let(:strategy) { described_class.new(env, scope) }
  let(:path) { '/v1/resource' }
  let(:email) { 'test@example.com' } # user.email
  let(:password) { 'MyPassW0r1' } # user.password
  let(:params) do
    {
      v2_user: {
        email: email,
        password: password
      }
    }
  end
  let(:env) { Rack::MockRequest.env_for(path, method: 'GET', params: params) }
  let(:not_authorized_exception) do
    Aws::CognitoIdentityProvider::Errors::NotAuthorizedException.new(nil,
                                                                     'Invalid Login')
  end
  describe '.valid?' do
    it 'returns true for sign in requests' do
      expect(strategy.valid?).to be_truthy
    end

    context 'with a non-sign in requests' do
      let(:params) { { foo: 'bar' } }

      it 'returns false' do
        expect(strategy.valid?).to be_falsey
      end
    end
  end

  describe '.authenticate' do
    let(:client) { double 'Client' }
    let(:initiate_auth_response) { double 'InitiateAuthResponse' }
    let(:authentication_result) { double 'AuthenticationResult' }
    let(:access_token) { 'ejXxXxX' }
    let(:refresh_token) { 'ej2XxXxX' }

    before do
      allow(Aws::CognitoIdentityProvider::Client).to receive(:new).and_return client
    end

    context 'with wrong credentials' do
      before do
        allow(client).to receive(:initiate_auth).and_raise not_authorized_exception
      end

      it 'call fail' do
        expect(strategy).to receive(:fail!).with(:invalid)
        strategy.authenticate!
      end
    end

    context 'with right credentials' do
      before do
        allow(client).to receive(:initiate_auth).and_return(initiate_auth_response)
        allow(initiate_auth_response).to receive(:authentication_result).and_return(authentication_result)
        allow(authentication_result).to receive(:access_token).and_return(access_token)
        allow(authentication_result).to receive(:refresh_token).and_return(refresh_token)
      end

      context 'with existing local user' do
        it 'call success with an existing user' do
          expect(strategy).to receive(:success!).with(user)
          strategy.authenticate!
        end
      end

      context 'referencing a new user' do
        before do
          config.user_repository = nil_user_repository
          allow(client).to receive(:get_user).and_return cognito_user
        end

        it 'calls the `after_local_user_not_found` callback' do
          expect(config.after_local_user_not_found).to receive(:call).with(cognito_user, pool_identifier)
          strategy.authenticate!
        end

        context 'with `after_local_user_not_found` returning nil' do
          before do
            config.after_local_user_not_found = Fixtures::Callback.after_user_local_not_found_nil
          end

          it 'fails! with :invalid' do
            expect(strategy).to receive(:fail!).with(:invalid)
            strategy.authenticate!
          end
        end

        context 'with `after_local_user_not_found` returning a user' do
          before do
            config.after_local_user_not_found = Fixtures::Callback.after_user_local_not_found_user
          end

          it 'success! with the given user' do
            expect(strategy).to receive(:success!).with(user)
            strategy.authenticate!
          end
        end
      end
    end

    context 'with a second user_pool configured and specified in params' do
      let(:clientIdPoolA) { 'AWS Cognito Client ID Pool A' }
      let(:clientIdSpecificPool) { 'AWS Cognito Client ID Specific Pool' }
      let(:user_pool_configurations) do
        {
          poolA: { region: 'EU_WEST_1', pool_id: 'PoolB_Id', client_id: clientIdPoolA },
          "#{pool_identifier}": { region: 'EU_WEST_1', pool_id: 'PoolA_Id', client_id: clientIdSpecificPool }
        }
      end

      let(:params) do
        {
          v2_user: {
            email: email,
            password: password,
            pool_identifier: pool_identifier.to_s
          }
        }
      end

      it 'creates a CognitoClient with the specified pool in scope' do
        expect(Warden::Cognito::CognitoClient).to receive(:scope).with(pool_identifier)
        strategy.authenticate!
      end

      context 'with right credentials' do
        before do
          allow(client).to receive(:initiate_auth).with(hash_including(client_id: clientIdSpecificPool))
                                                  .and_return(initiate_auth_response)
          allow(initiate_auth_response).to receive(:authentication_result).and_return(authentication_result)
          allow(authentication_result).to receive(:access_token).and_return(access_token)
          allow(authentication_result).to receive(:refresh_token).and_return(refresh_token)
        end

        context 'with existing local user' do
          it 'call success with an existing user' do
            expect(strategy).to receive(:success!).with(user)
            strategy.authenticate!
          end
        end
      end
    end
  end
end
