//
//  File.swift
//  
//
//  Created by asc on 6/17/20.
//

public enum OAuth2WrapperErrors: Error {
    case missingOAuth2AuthURL
    case missingOAuth2TokenURL
    case missingOAuth2ClientID
    case missingOAuth2ClientSecret
    case missingOAuth2Scope
    case keychainError
}
