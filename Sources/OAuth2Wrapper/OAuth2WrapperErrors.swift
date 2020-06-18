public enum OAuth2WrapperErrors: Error {
    case missingOAuth2AuthURL
    case missingOAuth2TokenURL
    case missingOAuth2ClientID
    case missingOAuth2ClientSecret
    case missingOAuth2Scope
    case missingOAuth2CallbackURL
    case missingKeychainLabel
    case keychainError
}
