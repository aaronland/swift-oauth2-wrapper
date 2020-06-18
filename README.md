# swift-oauth2-wrapper

Swift package around the OAuthSwift package with local caching and persisting of tokens to a user's Keychain. 

## Important

Work in progress. Proper documentation to follow, specifically about how to configure OAuth2 (client) crendetials and configuring (OAuth2) callbacks.

## Example

```
import Foundation
import OAuth2Wrapper
import OAuthSwift

func DoAuth() {

    let result = NewOAuth2WrapperConfigFromBundle(bundle: Bundle.main, prefix: "MyApp")
        
    switch result {
    case .failure(let error):
        print(error)
        return
    case .success(let config):
        let wrapper = OAuth2Wrapper(config: config)
        wrapper.GetAccessToken(completion: GotAuth)
    }
}

func GotAuth(result: Result<OAuthSwiftCredential, Error>){

    switch result {
    case .failure(let error):
        print(error)
    case .success(let creds):
        print(creds.oauthToken)
    }
}

## See also

* https://github.com/OAuthSwift/OAuthSwift
* https://github.com/jrendel/SwiftKeychainWrapper