//
//  File.swift
//  
//
//  Created by asc on 6/17/20.
//

import Foundation

public struct OAuth2WrapperConfig {
    
    public var AuthURL: String
    public var TokenURL: String
    public var ClientID: String
    public var ClientSecret: String
    public var Scope: String
    public var CallbackURL: String
}

public func NewOAuth2WrapperConfigFromBundle(bundle: Bundle, prefix: String?) -> Result<OAuth2WrapperConfig, Error> {
    
    var with_prefix = "OAuth2"
    
    if (prefix != nil) && prefix != "" {
            with_prefix = prefix!
    }
    
    let key_auth_url = String(format: "%@AuthURL", with_prefix)
    let key_token_url = String(format: "%@TokenURL", with_prefix)
    let key_client_id = String(format: "%@ClientID", with_prefix)
    let key_client_secret = String(format: "%@ClientSecret", with_prefix)
    let key_scope = String(format: "%@Scope", with_prefix)
    
    let oauth2_auth_url = bundle.object(forInfoDictionaryKey: key_auth_url) as? String
    let oauth2_token_url = bundle.object(forInfoDictionaryKey: key_token_url) as? String
    let oauth2_client_id = bundle.object(forInfoDictionaryKey: key_client_id) as? String
    var oauth2_client_secret = bundle.object(forInfoDictionaryKey: key_client_secret) as? String
    let oauth2_scope = bundle.object(forInfoDictionaryKey: key_scope) as? String
    
    if oauth2_auth_url == nil || oauth2_auth_url == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2AuthURL)
    }
    
    if oauth2_token_url == nil || oauth2_token_url == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2TokenURL)
    }
    
    if oauth2_client_id == nil || oauth2_client_id == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2ClientID)
    }
    
    if oauth2_client_secret == nil || oauth2_client_secret == "" {
        oauth2_client_secret = ""
    }
    
    if oauth2_scope == nil || oauth2_scope == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2Scope)
    }
    
    let cfg = OAuth2WrapperConfig(
        AuthURL: oauth2_auth_url!,
        TokenURL: oauth2_token_url!,
        ClientID: oauth2_client_id!,
        ClientSecret: oauth2_client_secret!,
        Scope: oauth2_scope!,
        CallbackURL: "fixme"
    )
    
    return .success(cfg)
}
