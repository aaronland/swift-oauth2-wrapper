import Foundation
import OAuthSwift

public enum OAuth2WrapperErrors: Error {
    case missingOAuth2AuthURL
    case missingOAuth2TokenURL
    case missingOAuth2ClientID
    case missingOAuth2ClientSecret
    case missingOAuth2Scope
}

public class OAuth2Wrapper {
    
    var callback_url: String
    var id: String
    
    var response_type = "token"
    var allow_missing_state = false
    var require_client_secret = true
    var allow_null_expires = false
    
    private var oauth2: OAuthSwift?
    private var credentials: OAuthSwiftCredential?
    
    init(id:String, callback_url: String) {
        self.id = id
        self.callback_url = callback_url        
    }
    
    public func GetAccessToken(completion: @escaping (Result<OAuthSwiftCredential, Error>) -> ()){
        
        let keychain_label = self.id
        
        if let creds = self.credentials {
            
            if !isExpired(credentials: creds) {
                completion(.success(creds))
                return
            }
        }
        
        if let data = KeychainWrapper.standard.data(forKey: keychain_label) {
            
            let decoder = JSONDecoder()
            var creds: OAuthSwiftCredential
            
            do {
                creds = try decoder.decode(OAuthSwiftCredential.self, from: data)
            } catch(let error) {
                completion(.failure(error))
                return
            }
            
            if !isExpired(credentials: creds) {
                completion(.success(creds))
                return
            }
        }
        
        func getStore(rsp: Result<OAuthSwiftCredential, Error>) {
            
            switch rsp {
            case .failure(let error):
                return completion(.failure(error))
            case .success(let credentials):
                
                let encoder = JSONEncoder()
                
                do {
                    let data = try encoder.encode(credentials)
                    KeychainWrapper.standard.set(data, forKey: keychain_label)
                } catch (let error) {
                    completion(.failure(error))
                }
                
                self.credentials = credentials
                completion(.success(credentials))
            }
        }
        
        self.GetNewAccessToken(completion: getStore)
    }
    
    public func GetNewAccessToken(completion: @escaping (Result<OAuthSwiftCredential,Error>) -> ()){
        
        print("GET NEW ACCESS TOKEN")
        
        let oauth2_auth_url = Bundle.main.object(forInfoDictionaryKey: "OAuth2AuthURL") as? String
        let oauth2_token_url = Bundle.main.object(forInfoDictionaryKey: "OAuth2TokenURL") as? String
        let oauth2_client_id = Bundle.main.object(forInfoDictionaryKey: "OAuth2ClientID") as? String
        let oauth2_client_secret = Bundle.main.object(forInfoDictionaryKey: "OAuth2ClientSecret") as? String
        let oauth2_scope = Bundle.main.object(forInfoDictionaryKey: "OAuth2Scope") as? String
        
        if oauth2_auth_url == nil || oauth2_auth_url == "" {
            completion(.failure(OAuth2WrapperErrors.missingOAuth2AuthURL))
            return
        }
        
        if oauth2_token_url == nil || oauth2_token_url == "" {
            completion(.failure(OAuth2WrapperErrors.missingOAuth2TokenURL))
            return
        }
        
        if oauth2_client_id == nil || oauth2_client_id == "" {
            completion(.failure(OAuth2WrapperErrors.missingOAuth2ClientID))
            return
        }
        
        if oauth2_client_secret == nil || oauth2_client_secret == "" {
            
            if self.require_client_secret {
                completion(.failure(OAuth2WrapperErrors.missingOAuth2ClientSecret))
                return
            }
        }
        
        if oauth2_scope == nil || oauth2_scope == "" {
            completion(.failure(OAuth2WrapperErrors.missingOAuth2Scope))
            return
        }
        
        let oauth2_state = UUID().uuidString
        
        let oauth2 = OAuth2Swift(
            consumerKey:    oauth2_client_id!,
            consumerSecret: oauth2_client_secret!,
            authorizeUrl:   oauth2_auth_url!,
            accessTokenUrl: oauth2_token_url!,
            responseType:   self.response_type
        )
        
        oauth2.allowMissingStateCheck = self.allow_missing_state
        
        // make sure we retain the oauth2 instance (I always forget this part...)
        self.oauth2 = oauth2
        
        oauth2.authorize(
            withCallbackURL: self.callback_url,
            scope: oauth2_scope!,
            state:oauth2_state
        ) { result in
            switch result {
            case .success(let (credential, _, _)):
                self.credentials = credential
                completion(.success(credential))
            case .failure(let error):
                // https://github.com/OAuthSwift/OAuthSwift/blob/master/Sources/OAuthSwiftError.swift
                // https://github.com/OAuthSwift/OAuthSwift/wiki/Interpreting-Error-Codes
                completion(.failure(error))
            }
        }
        
    }
    
    private func isExpired(credentials: OAuthSwiftCredential) -> Bool {
        
        var is_expired = credentials.isTokenExpired()
        
        if is_expired && self.allow_null_expires {
            
            let dt = credentials.oauthTokenExpiresAt!
            
            // Cooper Hewitt
            
            if dt.timeIntervalSince1970 < 1.0 {
                is_expired = false
            }
        }
        
        return is_expired
    }
}
