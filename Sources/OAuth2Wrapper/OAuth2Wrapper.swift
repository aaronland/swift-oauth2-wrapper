import Foundation
import Logging
import OAuthSwift

public class OAuth2Wrapper {
   
    private var oauth2: OAuthSwift?
    private var credentials: OAuthSwiftCredential?
    
    private var config: OAuth2WrapperConfig?
    
    private var callback_url: String
    private var id: String
    
    public var response_type = "token"
    public var allow_missing_state = false
    public var require_client_secret = true
    public var allow_null_expires = false
    public var add_to_keychain = true
    
    public var logger = Logger(label: "aaronland.swift-oauth2-wrapper")
    
    public init(id:String, config: OAuth2WrapperConfig) {
        self.id = id
        self.config! = config
    }
    
    public func GetAccessToken(completion: @escaping (Result<OAuthSwiftCredential, Error>) -> ()){
        
        self.logger.debug("Get access token")
        
        let keychain_label = self.id
        
        if let creds = self.credentials {
            
            self.logger.debug("Have cached credentials.")
            
            if !isExpired(credentials: creds) {
                completion(.success(creds))
                return
            }
            
            self.logger.debug("Cache credentials are expired.")
        }
        
        if !self.add_to_keychain {
            self.GetNewAccessToken(completion: completion)
            return
        }
        
        if let data = KeychainWrapper.standard.data(forKey: keychain_label) {
            
            self.logger.debug("Have stored credentials with ID \(keychain_label).")
            
            let decoder = JSONDecoder()
            var creds: OAuthSwiftCredential
            
            do {
                creds = try decoder.decode(OAuthSwiftCredential.self, from: data)
            } catch(let error) {
                self.logger.error("Store credentials could not be decoded, \(error).")
                completion(.failure(error))
                return
            }
            
            if !isExpired(credentials: creds) {
                completion(.success(creds))
                return
            }
            
            self.logger.debug("Stored credentials are expired.")
        }
        
        func getStore(rsp: Result<OAuthSwiftCredential, Error>) {
            
            switch rsp {
            case .failure(let error):
                self.logger.error("Failed to generate new access token, \(error).")
                return completion(.failure(error))
            case .success(let credentials):
                
                self.logger.debug("Generated new access token.")
                let encoder = JSONEncoder()
                
                var data: Data?
                
                do {
                    data = try encoder.encode(credentials)
                } catch (let error) {
                    self.logger.error("Failed to store new access token, \(error).")
                    completion(.failure(error))
                }
                
                let ok = KeychainWrapper.standard.set(data!, forKey: keychain_label)

                if !ok {
                    self.logger.error("Failed to store new credentials.")
                    completion(.failure(OAuth2WrapperErrors.keychainError))
                    return
                }
                
                self.logger.debug("Stored new credentials with ID \(keychain_label).")
                
                self.credentials = credentials
                completion(.success(credentials))
            }
        }
        
        self.GetNewAccessToken(completion: getStore)
    }
    
    public func GetNewAccessToken(completion: @escaping (Result<OAuthSwiftCredential,Error>) -> ()){
        
        let oauth2_state = UUID().uuidString
        
        let oauth2 = OAuth2Swift(
            consumerKey:    self.config!.ClientID,
            consumerSecret: self.config!.ClientSecret,
            authorizeUrl:   self.config?.AuthURL,
            accessTokenUrl: self.config?.TokenURL,
            responseType:   self.response_type
        )
        
        oauth2.allowMissingStateCheck = self.allow_missing_state
        
        // make sure we retain the oauth2 instance (I always forget this part...)
        self.oauth2 = oauth2
        
        self.logger.debug("Dispatch OAuth2 authorization request.")
        
        oauth2.authorize(
            withCallbackURL: self.config?.CallbackURL,
            scope: self.config?.Scope,
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
