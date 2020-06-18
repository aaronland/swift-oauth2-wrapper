import Foundation

public struct OAuth2WrapperConfig {
    
    public var AuthURL: String
    public var TokenURL: String
    public var CallbackURL: String
    public var ClientID: String
    public var ClientSecret: String
    public var Scope: String
    
    public var ResponseType = "token"
    public var AllowMissingState = false
    public var AllowNullExpires = false
    public var AddToKeychain = true
    public var KeychainLabel: String
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
    let key_callback_url = String(format: "%@CallbackURL", with_prefix)
    let key_keychain_label = String(format: "%@KeychainLabel", with_prefix)
    
    let auth_url = bundle.object(forInfoDictionaryKey: key_auth_url) as? String
    let token_url = bundle.object(forInfoDictionaryKey: key_token_url) as? String
    let callback_url = bundle.object(forInfoDictionaryKey: key_callback_url) as? String

    let client_id = bundle.object(forInfoDictionaryKey: key_client_id) as? String
    var client_secret = bundle.object(forInfoDictionaryKey: key_client_secret) as? String
    let scope = bundle.object(forInfoDictionaryKey: key_scope) as? String

    let keychain_label = bundle.object(forInfoDictionaryKey: key_keychain_label) as? String

    if auth_url == nil || auth_url == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2AuthURL)
    }
    
    if token_url == nil || token_url == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2TokenURL)
    }
    
    if callback_url == nil || callback_url == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2CallbackURL)
    }
    
    if client_id == nil || client_id == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2ClientID)
    }
    
    if client_secret == nil || client_secret == "" {
        client_secret = ""
    }
    
    if scope == nil || scope == "" {
        return .failure(OAuth2WrapperErrors.missingOAuth2Scope)
    }

    if keychain_label == nil || keychain_label == "" {
        return .failure(OAuth2WrapperErrors.missingKeychainLabel)
    }
    
    let cfg = OAuth2WrapperConfig(
        AuthURL: auth_url!,
        TokenURL: token_url!,
        CallbackURL: callback_url!,
        ClientID: client_id!,
        ClientSecret: client_secret!,
        Scope: scope!,
        KeychainLabel: keychain_label!
    )
    
    return .success(cfg)
}
